"""The Helm chart (deploy/helm/kubeheal) must render the same objects as the kustomize install."""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/kubeheal"
pytestmark = pytest.mark.skipif(not (shutil.which("helm") and shutil.which("kubectl")), reason="helm/kubectl not on PATH")


def load(out: str) -> dict:
    objs = {(d["kind"], d["metadata"].get("namespace", ""), d["metadata"]["name"]): d for d in yaml.safe_load_all(out) if d}
    for d in objs.values():
        d["metadata"].get("labels", {}).pop("app.kubernetes.io/managed-by", None)
        d["metadata"].pop("annotations", None)   # kustomize/helm bookkeeping only
    return objs


def helm(*args: str) -> dict:
    r = subprocess.run(["helm", "template", "kubeheal", str(CHART), "-n", "kubeheal", *args], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return load(r.stdout)


def kustomize(path: Path) -> dict:
    r = subprocess.run(["kubectl", "kustomize", str(path)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return load(r.stdout)


def same(a: dict, b: dict) -> None:
    assert a.keys() == b.keys()
    assert not [k for k in a if a[k] != b[k]], [k for k in a if a[k] != b[k]]


def test_dev_matches_kustomize():
    same(helm(), kustomize(ROOT / "deploy/k8s"))


def test_production_matches_overlay():
    same(helm("-f", str(CHART / "values-production.yaml")), kustomize(ROOT / "deploy/k8s/overlays/production"))


def test_falco_matches_component():
    with tempfile.TemporaryDirectory(dir=ROOT / "deploy/k8s/overlays", prefix=".tmp.") as d:   # kustomize bases must be relative
        (Path(d) / "kustomization.yaml").write_text("resources: [../../base]\ncomponents: [../../components/falco-source]\n")
        same(helm("--set", "eventSource=falco"), kustomize(Path(d)))


def test_k3d_values_are_dev_without_the_namespace():
    dev = helm()
    del dev[("Namespace", "", "kubeheal")]
    same(helm("-f", str(CHART / "values-k3d.yaml")), dev)


def test_modes_and_images_come_from_values():
    out = helm("--set", "mode=observe", "--set", "images.agents=r.example/agents:9")
    fusion = out[("Deployment", "kubeheal", "kubeheal-fusion-agent")]["spec"]["template"]["spec"]["containers"][0]
    assert {"name": "KUBEHEAL_MODE", "value": "observe"} in fusion["env"] and fusion["image"] == "r.example/agents:9"


def test_ingress_requires_tls_and_alerts_secret_is_opt_in():
    bad = subprocess.run(["helm", "template", "k", str(CHART), "--set", "ingress.enabled=true", "--set", "ingress.host=d.example"],
                         capture_output=True, text=True)
    assert bad.returncode != 0 and "TLS" in bad.stderr
    ok = helm("--set", "ingress.enabled=true", "--set", "ingress.host=d.example", "--set", "ingress.tlsSecretName=t",
              "--set", "alerts.webhookUrl=https://hooks.example/x")
    assert ("Ingress", "kubeheal", "kubeheal-dashboard") in ok and ("Secret", "kubeheal", "kubeheal-alerts") in ok
    assert ("Ingress", "kubeheal", "kubeheal-dashboard") not in helm() and ("Secret", "kubeheal", "kubeheal-alerts") not in helm()
