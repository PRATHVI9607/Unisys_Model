"""
Executor configuration for the P7 remediation paths.
====================================================
Numbers that the spec fixes are constants in the module that uses them (3 canary windows, snapshots
every 5 minutes, keep 12). The settings below are not in the spec. On 2026-11-11 the project owner chose
the defaults in the last column: they are CHOSEN DEFAULTS, NOT MEASUREMENTS, tunable through the
environment (the Helm values set the same ones). The defaults apply when the variable is absent from
the process environment. A variable that is set but empty or invalid is NOT replaced by the default: the
path that needs it escalates to a human BEFORE it writes anything (see `ConfigMissing`), so the
fail-closed behaviour is kept. An `ExecConfig` built from an explicit mapping (tests) has no defaults.

| Variable             | Needed by             | Meaning                                       | Default (chosen)                                            |
|----------------------|-----------------------|-----------------------------------------------|-------------------------------------------------------------|
| CANARY_WINDOW_S      | drift canary          | length of one observation window, seconds     | 30                                                          |
| ROLLOUT_TIMEOUT_S    | drift, restore        | how long to wait for a rollout or scale       | 180                                                         |
| ROLLOUT_POLL_S       | drift, restore        | poll interval while waiting, seconds          | 5                                                           |
| SNAPSHOT_CLASS       | snapshots, forensic   | VolumeSnapshotClass name (cluster specific)   | csi-hostpath-snapclass (P10 creates a class with this name) |
| PROMETHEUS_URL       | default metric source | base URL of Prometheus                        | http://prometheus-operated.monitoring.svc.cluster.local:9090 |
"""

import os
from typing import Mapping, Optional


class ConfigMissing(Exception):
    """A required setting is absent or invalid. `name` is the environment variable."""

    def __init__(self, name: str, why: str = "not set"):
        super().__init__(f"{name} {why}")
        self.name = name


# Chosen defaults (owner decision 2026-11-11), not measurements. See the module docstring.
DEFAULTS = {
    "CANARY_WINDOW_S": "30",
    "ROLLOUT_TIMEOUT_S": "180",
    "ROLLOUT_POLL_S": "5",
    "SNAPSHOT_CLASS": "csi-hostpath-snapclass",
    "CONTAIN_FREEZE_TIMEOUT_S": "10",
    "PROMETHEUS_URL": "http://prometheus-operated.monitoring.svc.cluster.local:9090",
    "RESTORE_ENTROPY_IMAGE_PULL_SECRETS": "",
}


class ExecConfig:
    def __init__(self, env: Optional[Mapping[str, str]] = None, use_defaults: Optional[bool] = None):
        self.env = os.environ if env is None else env
        # defaults only for the real process environment unless asked otherwise
        self.use_defaults = (env is None) if use_defaults is None else use_defaults

    def _get(self, name: str):
        """Value of a setting: the variable if present (even if empty), else the chosen default."""
        if name in self.env:
            return self.env.get(name)
        return DEFAULTS.get(name) if self.use_defaults else None

    def _positive_float(self, name: str) -> float:
        raw = self._get(name)
        if raw is None or str(raw).strip() == "":
            raise ConfigMissing(name)
        try:
            val = float(raw)
        except ValueError:
            raise ConfigMissing(name, f"is not a number: {raw!r}")
        if val <= 0:
            raise ConfigMissing(name, f"must be positive: {raw!r}")
        return val

    @property
    def canary_window_s(self) -> float:
        return self._positive_float("CANARY_WINDOW_S")

    @property
    def rollout_timeout_s(self) -> float:
        return self._positive_float("ROLLOUT_TIMEOUT_S")

    @property
    def rollout_poll_s(self) -> float:
        return self._positive_float("ROLLOUT_POLL_S")

    @property
    def freeze_timeout_s(self) -> float:
        """How long the Executor waits for the Security Agent's verified freeze answer (V5-S5)."""
        return self._positive_float("CONTAIN_FREEZE_TIMEOUT_S")

    @property
    def snapshot_class(self) -> str:
        val = (self._get("SNAPSHOT_CLASS") or "").strip()
        if not val:
            raise ConfigMissing("SNAPSHOT_CLASS")
        return val

    @property
    def prometheus_url(self) -> Optional[str]:
        return (self._get("PROMETHEUS_URL") or "").strip() or None
