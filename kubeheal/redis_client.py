"""One Redis client factory for the agents and the dashboard: plain REDIS_URL, or Sentinel-managed HA.

REDIS_SENTINELS="host:port,host:port" switches to Sentinel: the master is resolved on every (re)connect,
with the component's ACL user and password taken from REDIS_URL (its host is then ignored). A failover shows
up as ConnectionError (redis-py turns READONLY on a demoted master into one), which the callers' retry loops
already handle; the same client object finds the new primary on its next call.
"""

from __future__ import annotations

import os
from urllib.parse import unquote, urlparse

import redis.asyncio as aioredis
from redis.asyncio.sentinel import Sentinel

_sentinels: dict[tuple, Sentinel] = {}   # one per process: a Sentinel holds a connection pool per sentinel host


def redis_client(url: str, socket_timeout: float, socket_connect_timeout: float) -> aioredis.Redis:
    kw = {"decode_responses": True, "socket_timeout": socket_timeout, "socket_connect_timeout": socket_connect_timeout}
    hosts = [h.strip() for h in os.environ.get("REDIS_SENTINELS", "").split(",") if h.strip()]
    if not hosts:
        return aioredis.from_url(url, **kw)
    u = urlparse(url)
    nodes = tuple((h.rpartition(":")[0], int(h.rpartition(":")[2])) for h in hosts)   # a bad entry fails at startup
    key = (nodes, url, socket_timeout, socket_connect_timeout)
    if key not in _sentinels:
        sentinel_kw = {k: v for k, v in kw.items() if k.startswith("socket_")}
        if pw := os.environ.get("REDIS_SENTINEL_PASSWORD"):
            sentinel_kw["password"] = pw
        _sentinels[key] = Sentinel(list(nodes), sentinel_kwargs=sentinel_kw, username=unquote(u.username or "") or None,
                                   password=unquote(u.password or "") or None, db=int(u.path.lstrip("/") or 0), **kw)
    return _sentinels[key].master_for(os.environ.get("REDIS_SENTINEL_MASTER", "kubeheal"))
