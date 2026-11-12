"""Kill switch ConfigMap access for the dashboard (S-KS-6).

`KubernetesModeStore.write_mode` is the ONLY place where the dashboard writes to Kubernetes. It patches
the single ConfigMap `kubeheal-mode` (key `mode`) in namespace `kubeheal`; it also reads the requested
namespace's labels to honor `kubeheal/mode`. The dashboard's observer role allows namespace reads, while its
admin role alone can patch the mode ConfigMap (k8s/kill-switch.yaml, k8s/rbac/rbac.yaml). Callers must have
passed `require_admin` before changing the global mode.

The store is injectable: tests pass a fake and never touch a cluster.
"""

from __future__ import annotations

from typing import Optional, Protocol

from agents.common.killswitch import ENFORCE, MODE_CONFIGMAP, MODE_KEY, MODE_NAMESPACE, TEST

VALID_MODES = (TEST, ENFORCE)


class ModeStore(Protocol):
    async def read_mode(self) -> Optional[str]: ...
    async def read_namespace_mode(self, namespace: str) -> Optional[str]: ...
    async def write_mode(self, mode: str) -> None: ...


class KubernetesModeStore:
    """kubernetes_asyncio backed store. The library is imported lazily so the dashboard still starts
    (with the kill switch reported as unreadable) in an image that does not ship it."""

    def __init__(self, namespace: str = MODE_NAMESPACE, name: str = MODE_CONFIGMAP):
        self.namespace = namespace
        self.name = name

    async def _client_module(self):
        from kubernetes_asyncio import client, config
        try:
            config.load_incluster_config()
        except Exception:
            await config.load_kube_config()
        return client

    async def read_mode(self) -> Optional[str]:
        client = await self._client_module()
        async with client.ApiClient() as api:
            cm = await client.CoreV1Api(api).read_namespaced_config_map(self.name, self.namespace)
        return (cm.data or {}).get(MODE_KEY)

    async def read_namespace_mode(self, namespace: str) -> Optional[str]:
        """Read the target namespace's stricter kill-switch label for baseline decisions."""
        client = await self._client_module()
        async with client.ApiClient() as api:
            obj = await client.CoreV1Api(api).read_namespace(namespace)
        labels = getattr(obj.metadata, "labels", None) or {}
        return labels.get("kubeheal/mode")

    async def write_mode(self, mode: str) -> None:
        """THE dashboard write path to Kubernetes: set `data.mode` of the kubeheal-mode ConfigMap."""
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be exactly one of {VALID_MODES}")
        client = await self._client_module()
        async with client.ApiClient() as api:
            core = client.CoreV1Api(api)
            await core.patch_namespaced_config_map(
                self.name, self.namespace, {"data": {MODE_KEY: mode}}
            )
