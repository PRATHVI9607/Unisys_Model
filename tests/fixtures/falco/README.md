# Falco replay fixtures

These files are HAND-WRITTEN. They were not captured from a running Falco. They follow the Falco JSON
output format (one JSON object per line: `hostname`, `output`, `output_fields`, `priority`, `rule`,
`source`, `tags`, `time`) so the replay path exercises the same parser as live Falco. Pod name, container
id, PIDs and timestamps are invented for the test; the rule names and the `fd.name` / `k8s.*` / `proc.pid`
field names match the Falco fields the rules in `k8s/falco-kubeheal-rules.yaml` output (checked by `tests/test_falco_rules_sync.py`). Lines starting with `#` are comments for readers; the
replay reader skips them.

| File | Content |
|---|---|
| `ransomware_pv_encrypt.jsonl` | 12 files: write then rename to `.locked`, then a ransom note, pid 4242 on `/data`. Rule outputs carry `evt.type` (what the rules should emit). |
| `ransomware_pv_encrypt_current_rules.jsonl` | The same attack with 10 files and no `evt.type`, which is what the OLD rules (before V5-S1) produced (their output strings do not reference `evt.type`). |
| `ransomware_pv_encrypt_new_rules.jsonl` | V5-S1. HAND-WRITTEN, NOT A REAL CAPTURE, shaped like what the rules in `k8s/falco-kubeheal-rules.yaml` emit with `k8s/falco-values.yaml` (`output_fields` only, null for fields that do not apply): per file one read open and one write open with flags, then a rename with `fs.path.source` and `fs.path.target` (`.locked`), 12 files, then a CRITICAL ransom note; 37 lines, pid 4242. The old rules emitted no open flags and no rename source, which is why the shipped model scored the old traces benign. Replayed in `tests/test_falco_new_rules_trace.py`; its fields are checked against the rules in `tests/test_falco_rules_sync.py`. |
| `benign_sensitive_read.jsonl` | A trusted process reading `/etc` files; no KubeHeal rule matches. |

When Falco runs on a machine, record real traces into this directory (`file_output` with `json_output: true`)
and keep the hand-written ones next to them, clearly separated by name.

Use: `FALCO_MODE=replay FALCO_REPLAY_PATH=tests/fixtures/falco/ransomware_pv_encrypt.jsonl`.
