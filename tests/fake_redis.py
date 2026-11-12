"""In-memory async Redis fake for the P6 tests: keys with expiry, hashes, sets, sorted sets and streams with
consumer groups (pending lists, delivery counts, idle time, XAUTOCLAIM, XCLAIM, XPENDING). The clock is a
plain number the test advances, so no test sleeps. Only the commands KubeHeal uses are implemented."""
import fnmatch  # noqa: F401  (kept for tests that extend the fake)


class FakeRedis:
    def __init__(self, store=None):
        self.now = 1_000_000.0           # seconds, advanced by tests
        self.store = dict(store or {})   # plain keys (strings)
        self.expiry = {}                 # key -> absolute time
        self.hashes, self.sets, self.zsets = {}, {}, {}
        self.streams = {}                # name -> [(id, fields)]
        self.groups = {}                 # (stream, group) -> {"next": index, "pending": {id: {...}}}
        self.acked, self.added = [], []  # (stream, id) / (stream, fields) logs, as the older fakes had
        self._seq = 0
        self.fail = {}                   # command name -> exception to raise (error injection)

    # ---- helpers -----------------------------------------------------------------------------------
    def advance(self, seconds):
        self.now += seconds

    def _maybe_fail(self, name):
        exc = self.fail.get(name)
        if exc is not None:
            raise exc

    def _alive(self, key):
        exp = self.expiry.get(key)
        if exp is not None and exp <= self.now:
            self.store.pop(key, None)
            self.expiry.pop(key, None)
        return key in self.store

    # ---- strings -----------------------------------------------------------------------------------
    async def get(self, key):
        self._maybe_fail("get")
        return self.store.get(key) if self._alive(key) else None

    async def set(self, key, value, nx=False, ex=None, px=None):
        self._maybe_fail("set")
        if nx and self._alive(key):
            return None
        self.store[key] = value
        self.expiry.pop(key, None)
        if ex is not None:
            self.expiry[key] = self.now + ex
        if px is not None:
            self.expiry[key] = self.now + px / 1000.0
        return True

    async def delete(self, *keys):
        n = 0
        for k in keys:
            n += int(self.store.pop(k, None) is not None) + int(self.hashes.pop(k, None) is not None) \
                + int(self.zsets.pop(k, None) is not None) + int(self.sets.pop(k, None) is not None)
        return n

    async def incr(self, key):
        self._maybe_fail("incr")
        value = int(await self.get(key) or 0) + 1
        self.store[key] = value
        return value

    async def expire(self, key, seconds):
        if key in self.store or key in self.hashes or key in self.zsets or key in self.sets:
            self.expiry[key] = self.now + seconds
            return True
        return False

    async def eval(self, script, n, key, token, *extra):
        if "kubeheal:publish_health_event" in script:
            stream, detail, marker = key, token, extra[0]
            if await self.get(marker) is not None:
                return 0
            # Match the Lua command order: a failed detail HSET must not leave a stream
            # entry. An XADD failure may leave the expiring detail hash for a retry.
            self._maybe_fail("hset")
            fields = extra[1:]
            payload = dict(zip(fields[::2], fields[1::2]))
            self.hashes[detail] = dict(payload)
            self.expiry[detail] = self.now + 86400
            self._maybe_fail("xadd")
            self._seq += 1
            entry_id = f"{int(self.now * 1000)}-{self._seq}"
            self.streams.setdefault(stream, []).append((entry_id, payload))
            self.added.append((stream, dict(payload)))
            self.store[marker] = entry_id
            self.expiry[marker] = self.now + 86400
            return 1
        if "kubeheal:record_security_score" in script:
            # Python mirror of RECORD_SECURITY_SCORE_LUA (agents/security_agent/agent.py); keep the two in step.
            model_scored, risk, ts_ms, ttl, publish = token, extra[0], extra[1], int(extra[2]), float(extra[3])
            now_ms, hold = int(ts_ms), int(extra[2]) * 1000
            previous = self.hashes.get(key, {})
            alive = self.expiry.get(key, 0) > self.now
            if model_scored == "true":
                false_ts = previous.get("false_ts_ms")
                if (false_ts and now_ms - int(false_ts) < hold and float(risk) < publish and alive):
                    return ""
                high, high_ts = previous.get("high_risk"), previous.get("high_ts_ms")
                if high and high_ts and now_ms - int(high_ts) < hold and float(high) > float(risk):
                    risk = high
                else:
                    previous["high_risk"], previous["high_ts_ms"] = risk, ts_ms
            else:
                previous["false_ts_ms"] = ts_ms
            previous.update({"sec_risk": risk, "model_scored": model_scored, "ts_ms": ts_ms})
            self.hashes[key] = previous
            self.expiry[key] = self.now + ttl
            return risk
        if await self.get(key) != token:
            return 0
        if "expire" in script:
            return 1
        self.store.pop(key, None)
        return 1

    async def aclose(self):
        return None

    # ---- hashes ------------------------------------------------------------------------------------
    async def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            h.update({str(k): str(v) for k, v in mapping.items()})
        if field is not None:
            h[str(field)] = str(value)
        return 1

    async def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    # ---- sets --------------------------------------------------------------------------------------
    async def sadd(self, key, *members):
        self._maybe_fail("sadd")
        s = self.sets.setdefault(key, set())
        before = len(s)
        s.update(members)
        return len(s) - before

    async def scard(self, key):
        self._maybe_fail("scard")
        return len(self.sets.get(key, ()))

    # ---- sorted sets -------------------------------------------------------------------------------
    async def zadd(self, key, mapping):
        self._maybe_fail("zadd")
        z = self.zsets.setdefault(key, {})
        added = sum(1 for m in mapping if m not in z)
        z.update({m: float(s) for m, s in mapping.items()})
        return added

    async def zremrangebyscore(self, key, lo, hi):
        z = self.zsets.get(key, {})
        lo = float("-inf") if lo == "-inf" else float(lo)
        hi = float("inf") if hi == "+inf" else float(hi)
        gone = [m for m, s in z.items() if lo <= s <= hi]
        for m in gone:
            del z[m]
        return len(gone)

    async def zcard(self, key):
        self._maybe_fail("zcard")
        return len(self.zsets.get(key, {}))

    # ---- streams -----------------------------------------------------------------------------------
    async def xadd(self, stream, fields, maxlen=None, approximate=True, id="*"):
        self._maybe_fail("xadd")
        self._seq += 1
        entry_id = f"{int(self.now * 1000)}-{self._seq}"
        self.streams.setdefault(stream, []).append((entry_id, dict(fields)))
        self.added.append((stream, dict(fields)))
        if maxlen is not None and len(self.streams[stream]) > maxlen:
            del self.streams[stream][: len(self.streams[stream]) - maxlen]
        return entry_id

    async def xgroup_create(self, stream, group, id="$", mkstream=False):
        if (stream, group) in self.groups:
            raise Exception("BUSYGROUP Consumer Group name already exists")
        if stream not in self.streams:
            if not mkstream:
                raise Exception("no such key")
            self.streams[stream] = []
        start = 0 if id == "0" else len(self.streams[stream])
        self.groups[(stream, group)] = {"next": start, "pending": {}}

    def _entry(self, stream, entry_id):
        for eid, fields in self.streams.get(stream, []):
            if eid == entry_id:
                return fields
        return None

    async def xreadgroup(self, group, consumer, streams, count=None, block=None):
        self._maybe_fail("xreadgroup")
        out = []
        for stream, pos in streams.items():
            g = self.groups[(stream, group)]
            entries = []
            if pos == ">":
                items = self.streams[stream][g["next"]:]
                if count:
                    items = items[:count]
                g["next"] += len(items)
                for eid, fields in items:
                    g["pending"][eid] = {"consumer": consumer, "at": self.now, "times": 1}
                    entries.append((eid, dict(fields)))
            else:
                for eid, meta in sorted(g["pending"].items()):
                    if meta["consumer"] == consumer:
                        entries.append((eid, dict(self._entry(stream, eid) or {})))
            if entries:
                out.append((stream, entries))
        return out

    async def xack(self, stream, group, *ids):
        g = self.groups.get((stream, group))
        n = 0
        for i in ids:
            self.acked.append((stream, i))
            if g and g["pending"].pop(i, None) is not None:
                n += 1
        return n

    def _claim(self, stream, group, consumer, ids, min_idle_ms, justid):
        g = self.groups[(stream, group)]
        claimed = []
        for eid in ids:
            meta = g["pending"].get(eid)
            if meta is None or (self.now - meta["at"]) * 1000 < min_idle_ms:
                continue
            meta["consumer"], meta["at"] = consumer, self.now
            if not justid:
                meta["times"] += 1
            claimed.append(eid)
        return claimed

    async def xautoclaim(self, name, groupname, consumername, min_idle_time, start_id="0-0", count=None,
                         justid=False):
        self._maybe_fail("xautoclaim")
        g = self.groups[(name, groupname)]
        key = lambda e: int(e.split("-")[0]) * 10**9 + int(e.split("-")[1])  # noqa: E731
        ids = [e for e in sorted(g["pending"], key=key) if key(e) >= key(start_id)]
        stale = [e for e in ids if (self.now - g["pending"][e]["at"]) * 1000 >= min_idle_time]
        batch = stale[:count] if count else stale
        claimed = self._claim(name, groupname, consumername, batch, min_idle_time, justid)
        rest = stale[len(batch):]
        nxt = rest[0] if rest else "0-0"
        entries = [(e, (None if justid else self._entry(name, e))) for e in claimed]
        if justid:
            entries = claimed
        return [nxt, entries, []]

    async def xclaim(self, name, groupname, consumername, min_idle_time, message_ids, idle=None,
                     time=None, retrycount=None, force=False, justid=False):
        claimed = self._claim(name, groupname, consumername, message_ids, min_idle_time, justid)
        return claimed if justid else [(e, dict(self._entry(name, e) or {})) for e in claimed]

    async def xpending_range(self, name, groupname, min, max, count, consumername=None, idle=None):
        g = self.groups[(name, groupname)]
        key = lambda e: int(e.split("-")[0]) * 10**9 + int(e.split("-")[1])  # noqa: E731
        rows = []
        for eid in sorted(g["pending"], key=key):
            if min != "-" and key(eid) < key(min):
                continue
            if max != "+" and key(eid) > key(max):
                continue
            meta = g["pending"][eid]
            rows.append({"message_id": eid, "consumer": meta["consumer"],
                         "time_since_delivered": int((self.now - meta["at"]) * 1000),
                         "times_delivered": meta["times"]})
        return rows[:count]

    def pending_ids(self, stream, group):
        return sorted(self.groups[(stream, group)]["pending"])
