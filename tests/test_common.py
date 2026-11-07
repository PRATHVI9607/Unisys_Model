"""agents.common.run: SIGTERM ends the agent cleanly (PID 1 would otherwise ignore it)."""

import asyncio
import os
import signal

from agents import common


def test_sigterm_cancels_main_cleanly():
    seen = []

    async def main():
        asyncio.get_running_loop().call_later(0.05, os.kill, os.getpid(), signal.SIGTERM)
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            seen.append("cancelled")      # finally/cleanup blocks run
            raise

    common.run(main)
    assert seen == ["cancelled"]


async def test_predict_batch_round_trip_and_failures(monkeypatch):
    from aiohttp import ClientSession, web
    from aiohttp.test_utils import TestServer

    pred = {"model_version": "v", "label": "benign", "risk": 0.1, "probabilities": {"benign": 1.0},
            "prediction_set": ["benign"], "uncertain": False}
    reply = {"status": 200, "n": None}

    async def handler(req: web.Request) -> web.Response:
        items = (await req.json())["items"]
        n = len(items) if reply["n"] is None else reply["n"]
        return web.json_response([pred] * n, status=reply["status"])

    app = web.Application()
    app.router.add_post("/v1/security/predict_batch", handler)
    async with TestServer(app) as srv, ClientSession() as s:
        monkeypatch.setattr(common, "INFERENCE_URL", str(srv.make_url("")).rstrip("/"))
        out = await common.predict_batch(s, "security", [{"n_events": 1.0}, {}])
        assert [p.label for p in out] == ["benign", "benign"]
        reply["n"] = 1                                       # wrong count: never misattribute predictions
        assert await common.predict_batch(s, "security", [{}, {}]) is None
        reply.update(n=None, status=503)
        assert await common.predict_batch(s, "security", [{}]) is None


def test_ensure_namespace_patches_labels_when_it_exists():
    import asyncio

    from kubernetes_asyncio.client.exceptions import ApiException

    from training.collect import common

    class Core:
        patched = None

        async def create_namespace(self, body):
            raise ApiException(status=409)

        async def patch_namespace(self, name, body):
            self.patched = (name, body)

    core = Core()
    asyncio.run(common.ensure_namespace(core))
    assert core.patched[0] == common.NS and core.patched[1]["metadata"]["labels"]["kubeheal.io/lab"] == "true"
