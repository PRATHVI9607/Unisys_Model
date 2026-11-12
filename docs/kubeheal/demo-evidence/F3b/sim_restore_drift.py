"""Offline check (read only, no cluster write): the golden baseline of prod/victim-app (read from Redis 2026-11-12)
against the spec a restore leaves behind (restore.py: new claim name, images pinned by digest). Uses the real
Health Agent diff and features, the shipped health bundle (spec diff only: no Prometheus window), the real decision
policy and the Executor's patch builder.  python docs/kubeheal/demo-evidence/F3b/sim_restore_drift.py <golden.json>"""
import copy, json, sys
sys.path.insert(0, ".")
from agents.health_agent import baseline
from agents.health_agent.agent import policy_violations, changed_paths, canonical_spec, METRIC_FEATURES
from kubeheal.features.health import health_features
from kubeheal.ml.bundle import ModelBundle
from agents.executor.drift import build_patch, validate_patch_target, PlanError
from agents.executor.restore import pin_image

golden = json.load(open(sys.argv[1]))
old = golden["spec"]
live = copy.deepcopy(old)
t = live["template"]["spec"]
DIGEST = "sha256:" + "ab" * 32
for v in t["volumes"]:
    if "persistentVolumeClaim" in v:
        v["persistentVolumeClaim"]["claimName"] = "victim-data-restore-inc-20261112-141554-1d76b1ed"   # name shape from restore.py
for c in t["containers"] + t.get("initContainers", []):
    c["image"] = pin_image(c["image"], DIGEST)                                               # pin_image shape
print("is_drifted:", baseline.is_drifted(golden, live))
changed = changed_paths(canonical_spec(old), canonical_spec(live))
print("changed paths:", changed)
print("policy violations:", policy_violations(old, baseline.drift_view(live)))
win = {}
feats = health_features(old, baseline.drift_view(live), win)
print("non-null features:", {k: v for k, v in feats.items() if v not in (None, 0, 0.0)})
bundle = ModelBundle.load_default("health")
pred = bundle.predict(bundle.restrict(feats))
print("model (spec diff only, no metrics):", pred.label, round(pred.risk, 4), pred.prediction_set, "uncertain=", pred.uncertain)
try:
    plan = build_patch(old, live, changed)
    print("patch plan drifted paths:", plan.drifted)
    try:
        validate_patch_target(live, baseline.drift_view(live), plan.target)
        print("validate_patch_target: ALLOWED (the old PVC would be put back)")
    except PlanError as e:
        print("validate_patch_target: REFUSED:", str(e)[:120])
except Exception as e:
    print("build_patch:", type(e).__name__, e)
print("forward JSON patch an auto_patch would apply:")
for op in plan.forward:
    print("  ", op["op"], op["path"], "->", op.get("value"))
from agents.fusion_agent.decision_policy import make_decision, DecisionInput
import inspect
print([p for p in inspect.signature(DecisionInput).parameters][:40])
print("decision policy on the model's spec-only answer (risk %.4f, label %s):" % (pred.risk, pred.label))
for tier in ("dev", "staging", "prod"):
    for mode in ("test", "enforce"):
        d = make_decision(DecisionInput(health_risk=pred.risk, health_label=pred.label, health_prediction_set=list(pred.prediction_set),
            sec_risk=0.0, sec_label="benign", sec_prediction_set=["benign"], sec_syscall_top="", correlation_score=0.0, compound_flag=False,
            namespace_tier=tier, circuit_breaker_containments=0, circuit_breaker_patches=0, models_ok=True, namespace_protected=False,
            metric_samples_seen=5000, burn_in_mode=False, nl_summary="", rollback_reasons=[], spec_changed=True, has_baseline=True,
            changed_fields=changed, security_fresh=False, mode=mode))
        print(f"  {tier:8s} {mode:8s} -> {d.decision.value} (adjusted {d.adjusted_score:.3f}, dry_run={d.dry_run})")
