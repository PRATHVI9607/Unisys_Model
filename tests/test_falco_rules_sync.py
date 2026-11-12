"""V5-S1: the Falco rules, the Falco values, the agent's normaliser and the recorded fixtures must agree.

Pure YAML and JSON parsing, no Falco binary. Falco only fills `output_fields` with the fields a rule's output string
references, so a field that the agent reads but no rule outputs is silently missing on live data: that is how the
shipped LightGBM bundle came to score a ransomware window benign (no open flags, no rename source).
"""
import inspect
import json
import re
from pathlib import Path

import pytest
import yaml

from agents.security_agent import falco_client as fc
from kubeheal.features.security import CAPTURED_GROUPS, OPEN_SYSCALLS, SYSCALL_GROUPS

ROOT = Path(__file__).resolve().parents[1]
RULES_FILE = ROOT / "k8s" / "falco-kubeheal-rules.yaml"
FALCO_YAML = ROOT / "k8s" / "falco.yaml"
VALUES_FILE = ROOT / "k8s" / "falco-values.yaml"
FIXTURES = ROOT / "tests" / "fixtures" / "falco"
NEW_RULES_TRACE = FIXTURES / "ransomware_pv_encrypt_new_rules.jsonl"

# Falco field names behind each v5 key of falco_client._normalise.
V5_FIELDS = {
    "syscall": "evt.type", "flags": "evt.arg.flags", "pid": "proc.pid", "fd_path": "fd.name",
    "fs_name": "fs.path.name", "fs_source": "fs.path.source", "fs_target": "fs.path.target",
    "pod": "k8s.pod.name", "namespace": "k8s.ns.name", "container_id": "container.id", "pod_uid": "k8s.pod.uid",
}
# Fields `_normalise` reads that are not under the rules' control: aliases for other event sources, and values Falco
# or its container plugin may attach on their own (the hand-written legacy fixtures carry evt.time and container.name).
ALIASES_AND_ATTACHED = {"syscall", "pid", "fd.path", "container.name", "evt.time"}
FALCO_ATTACHED = {"evt.time", "container.name"}


def load_rules(path=RULES_FILE):
    items = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return {
        "rules": {i["rule"]: i for i in items if "rule" in i},
        "macros": {i["macro"]: i["condition"] for i in items if "macro" in i},
        "lists": {i["list"]: i["items"] for i in items if "list" in i},
    }


def output_fields(rule) -> set[str]:
    """Field names the rule's output string references (`%evt.type`, `%fs.path.source`, ...)."""
    return set(re.findall(r"%([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)", rule["output"]))


def expanded_condition(rule, macros) -> str:
    cond = " ".join(str(rule["condition"]).split())
    for _ in range(10):                       # macros may use macros
        new = cond
        for name, body in macros.items():
            new = re.sub(rf"\b{re.escape(name)}\b", " ".join(str(body).split()), new)
        if new == cond:
            break
        cond = new
    return cond


def condition_evt_types(rule, macros) -> set[str]:
    out: set[str] = set()
    for group in re.findall(r"evt\.type in \(([^)]*)\)", expanded_condition(rule, macros)):
        out |= {x.strip() for x in group.split(",") if x.strip()}
    return out


@pytest.fixture(scope="module")
def parsed():
    return load_rules()


def test_the_rules_file_has_the_three_expected_rules(parsed):
    assert set(parsed["rules"]) == {
        "KubeHeal Ransom Note Dropped", "KubeHeal Ransomware Mass Rename", "KubeHeal Data File Activity"}


def test_priorities_and_the_ransom_note_trigger_semantics_are_kept(parsed):
    """syscall_window.py triggers on its own for a CRITICAL rule whose name contains "ransom"; the warning rules
    only count towards the burst threshold and the activity rule must never be one of them."""
    prio = {n: r["priority"] for n, r in parsed["rules"].items()}
    assert prio["KubeHeal Ransom Note Dropped"] == "CRITICAL"
    assert prio["KubeHeal Ransomware Mass Rename"] == "WARNING"
    assert prio["KubeHeal Data File Activity"] == "NOTICE"
    for name, p in prio.items():
        if "ransom" in name.lower():
            assert p in ("CRITICAL", "WARNING")
    assert "ransom" not in "KubeHeal Data File Activity".lower()     # a NOTICE open must never trigger a check alone


def test_every_field_the_normaliser_reads_is_emitted_by_the_relevant_rules(parsed):
    """(a) The v5 mapping needs flags (opens), fs_source and fs_target (renames), fs_name (path-based calls),
    fd_path, pid, pod, namespace, container id, pod uid. Every rule outputs the whole set."""
    emitted = {n: output_fields(r) for n, r in parsed["rules"].items()}
    needed = set(V5_FIELDS.values())
    for name, fields in emitted.items():
        assert needed <= fields, f"{name} lacks {sorted(needed - fields)}"
    # the rules that carry the open flags and both rename paths
    assert "evt.arg.flags" in emitted["KubeHeal Data File Activity"]
    assert "evt.arg.flags" in emitted["KubeHeal Ransom Note Dropped"]
    assert {"fs.path.source", "fs.path.target"} <= emitted["KubeHeal Ransomware Mass Rename"]
    assert "fs.path.name" in emitted["KubeHeal Data File Activity"]


def test_the_normaliser_reads_no_field_that_the_table_does_not_know():
    """If `_normalise` starts reading another field, this fails until the rules (and V5_FIELDS) are updated."""
    src = inspect.getsource(fc._normalise)
    read = set(re.findall(r'of\.get\("([^"]+)"\)', src))
    assert read - ALIASES_AND_ATTACHED == set(V5_FIELDS.values()), sorted(read ^ set(V5_FIELDS.values()))


def test_the_rule_evt_types_match_the_models_captured_syscall_groups(parsed):
    """v5's test idea: the syscalls the rules hook are exactly the raw syscalls behind CAPTURED_GROUPS (opens stand
    for the read and write groups), and no read()/write() is hooked."""
    hooked: set[str] = set()
    for rule in parsed["rules"].values():
        hooked |= condition_evt_types(rule, parsed["macros"])
    captured: set[str] = set()
    for group in CAPTURED_GROUPS:
        for name in SYSCALL_GROUPS[group]:
            captured |= set(OPEN_SYSCALLS) if name in ("open_r", "open_w") else {name}
    assert hooked == captured, (sorted(hooked - captured), sorted(captured - hooked))
    assert not hooked & {"read", "write", "pread", "pwrite", "pwritev"}


def test_the_rules_are_disjoint_on_evt_type_or_note_name(parsed):
    """One syscall must give one event even with rule_matching=all: the activity rule excludes note opens and does not
    list renames; the rename rule has only renames."""
    macros = parsed["macros"]
    act = parsed["rules"]["KubeHeal Data File Activity"]
    ren = parsed["rules"]["KubeHeal Ransomware Mass Rename"]
    note = parsed["rules"]["KubeHeal Ransom Note Dropped"]
    assert not condition_evt_types(act, macros) & condition_evt_types(ren, macros)
    assert not condition_evt_types(note, macros) & condition_evt_types(ren, macros)
    assert "not (" in expanded_condition(act, macros) and "kh_note_name" in act["condition"]
    assert "kh_note_name" in note["condition"]


def test_the_falco_values_hook_every_rule_syscall_and_no_read_write():
    values = yaml.safe_load(VALUES_FILE.read_text(encoding="utf-8"))["falco"]
    custom = set(values["base_syscalls"]["custom_set"])
    parsed_rules = load_rules()
    hooked: set[str] = set()
    for rule in parsed_rules["rules"].values():
        hooked |= condition_evt_types(rule, parsed_rules["macros"])
    assert hooked <= custom, sorted(hooked - custom)
    assert not custom & {"read", "write", "pread", "pwrite", "pwritev"}
    assert values["json_output"] is True and values["json_include_output_fields_property"] is True
    assert values["file_output"]["filename"] == "/var/run/falco/events.jsonl"


def test_the_configmap_in_falco_yaml_carries_the_same_rules():
    docs = [d for d in yaml.safe_load_all(FALCO_YAML.read_text(encoding="utf-8")) if d]
    cm = next(d for d in docs if d.get("kind") == "ConfigMap")
    embedded = yaml.safe_load(cm["data"]["kubeheal_rules.yaml"])
    assert embedded == yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))


def fixture_files():
    return sorted(FIXTURES.glob("*.jsonl"))


def fixture_events(path):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield json.loads(line)


def test_there_are_recorded_fixtures():
    assert NEW_RULES_TRACE in fixture_files() and len(fixture_files()) >= 4


@pytest.mark.parametrize("path", fixture_files(), ids=lambda p: p.name)
def test_fixture_events_use_only_fields_some_rule_emits(path, parsed):
    """(b) A recorded or hand-written event may not carry a field that no rule can produce (besides the two that
    Falco itself may attach). Events of rules outside this file (the benign trace) are skipped."""
    ours = {name: output_fields(r) for name, r in parsed["rules"].items()}
    allowed_anywhere = set().union(*ours.values()) | FALCO_ATTACHED
    checked = 0
    for evt in fixture_events(path):
        keys = set(evt.get("output_fields", {}))
        assert keys <= allowed_anywhere, f"{path.name}: {sorted(keys - allowed_anywhere)}"
        if evt.get("rule") in ours:
            checked += 1
    if path.name != "benign_sensitive_read.jsonl":
        assert checked > 0


def test_the_new_rules_trace_is_strict_about_which_rule_emits_which_field(parsed):
    ours = {name: output_fields(r) for name, r in parsed["rules"].items()}
    events = list(fixture_events(NEW_RULES_TRACE))
    assert len(events) == 37
    for evt in events:
        assert evt["rule"] in ours, evt["rule"]
        assert set(evt["output_fields"]) <= ours[evt["rule"]]           # no allowance for Falco-attached fields
        assert "output" not in evt and "tags" not in evt                # falco-values.yaml switches them off
    assert NEW_RULES_TRACE.read_text(encoding="utf-8").splitlines()[0].startswith("# HAND-WRITTEN, NOT A REAL CAPTURE")


def test_the_rules_say_which_fields_they_emit_in_the_output_string(parsed):
    for rule in parsed["rules"].values():
        assert "%evt.type" in rule["output"] and "%proc.pid" in rule["output"]
