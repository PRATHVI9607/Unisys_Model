"""
Executor configuration for the P7 remediation paths.
====================================================
Numbers that the spec fixes are constants in the module that uses them (3 canary windows, snapshots
every 5 minutes, keep 12). Numbers the spec does NOT give are required environment variables: the
Executor will not guess them. A path that needs a missing value escalates to a human BEFORE it
writes anything (see `ConfigMissing`).

| Variable             | Needed by             | Meaning                                                  |
|----------------------|-----------------------|----------------------------------------------------------|
| CANARY_WINDOW_S      | drift canary          | length of one observation window, seconds                |
| ROLLOUT_TIMEOUT_S    | drift, restore        | how long to wait for a rollout or scale to settle        |
| ROLLOUT_POLL_S       | drift, restore        | poll interval while waiting, seconds                     |
| SNAPSHOT_CLASS       | snapshots, forensic   | VolumeSnapshotClass name (cluster specific)              |
| PROMETHEUS_URL       | default metric source | base URL of Prometheus (only if no source is injected)   |
"""

import os
from typing import Mapping, Optional


class ConfigMissing(Exception):
    """A required setting is absent or invalid. `name` is the environment variable."""

    def __init__(self, name: str, why: str = "not set"):
        super().__init__(f"{name} {why}")
        self.name = name


class ExecConfig:
    def __init__(self, env: Optional[Mapping[str, str]] = None):
        self.env = os.environ if env is None else env

    def _positive_float(self, name: str) -> float:
        raw = self.env.get(name)
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
    def snapshot_class(self) -> str:
        val = (self.env.get("SNAPSHOT_CLASS") or "").strip()
        if not val:
            raise ConfigMissing("SNAPSHOT_CLASS")
        return val

    @property
    def prometheus_url(self) -> Optional[str]:
        return (self.env.get("PROMETHEUS_URL") or "").strip() or None
