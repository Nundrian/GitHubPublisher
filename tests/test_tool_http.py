"""HTTP service + native Tool, wired together over real loopback HTTP.
The browser confirmation is SIMULATED by passing fake __event_call__ callables
that return what Open WebUI 0.12.5 returns (True on Confirm, False on Cancel,
{'error': ...} on disconnect/timeout)."""

import asyncio
import importlib.util
import json
import os
import socket
import threading
import urllib.error
import urllib.request

import pytest

pydantic = pytest.importorskip("pydantic")

from conftest import ROOT
from publisher.server import ensure_token, make_handler
from http.server import ThreadingHTTPServer

ADMIN = {"id": "u-admin", "role": "admin", "name": "admin"}


def load_tool():
    spec = importlib.util.spec_from_file_location("ghpub_tool", os.path.join(ROOT, "openwebui", "github_publisher_tool.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Tools()


@pytest.fixture
def served(env):
    pub = env.publisher()
    token = ensure_token(pub.cfg.token_file)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(pub, token))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    tool = load_tool()
    tool.valves.service_url = f"http://127.0.0.1:{port}"
    tool.valves.service_token = token
    tool.valves.confirm_timeout_s = 10
    yield env, pub, tool, port, token
    httpd.shutdown()


def run(coro):
    return asyncio.run(coro)


def http(port, method, path, token=None, body=None, headers=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    if token:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method, headers=h,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_http_auth_and_origin(served):
    env, pub, tool, port, token = served
    assert http(port, "GET", "/v1/status")[0] == 401
    assert http(port, "GET", "/v1/status", token="wrong" * 10)[0] == 401
    assert http(port, "GET", "/v1/status", token=token, headers={"Origin": "http://evil"})[0] == 403
    code, body = http(port, "POST", "/v1/prepare", token=token, body={"project": "x" * 5000})
    assert code == 413
    code, body = http(port, "GET", "/v1/status", token=token)
    assert code == 200 and body["projects"][0]["alias"] == "demo"
    assert token not in json.dumps(body)


def _prepare(tool):
    r = json.loads(run(tool.prepare_publish("demo", __user__=ADMIN)))
    assert r["status"] == "ready", r
    return r["plan_id"]


@pytest.mark.parametrize("answer", [False, {"error": "Client session disconnected."},
                                    {"error": "Event call timed out."}, "yes", 1, None],
                         ids=["cancel", "disconnected", "timed-out", "string-yes", "int-1", "none"])
def test_tool_publish_fails_closed_unless_confirmed(served, answer):
    env, pub, tool, port, token = served
    pid = _prepare(tool)
    seen = []

    async def event_call(ev):
        seen.append(ev)
        return answer
    r = json.loads(run(tool.publish_reviewed(pid, __user__=ADMIN, __event_call__=event_call)))
    assert r["result"] == "not_approved"
    assert seen and seen[0]["type"] == "confirmation"
    assert "Nundrian/Demo" in seen[0]["data"]["message"] and "PRIVATE" in seen[0]["data"]["message"]
    assert not os.path.exists(env.remote_gd())


def test_tool_publish_timeout_is_no(served):
    env, pub, tool, port, token = served
    pid = _prepare(tool)
    tool.valves.confirm_timeout_s = 10

    async def never(ev):
        await asyncio.sleep(3600)
    tool.valves.confirm_timeout_s = 1   # below the 10s floor -> floor applies; patch for speed
    import types
    orig = asyncio.wait_for

    async def fast_wait_for(aw, timeout):
        return await orig(aw, 0.2)
    asyncio.wait_for = fast_wait_for
    try:
        r = json.loads(run(tool.publish_reviewed(pid, __user__=ADMIN, __event_call__=never)))
    finally:
        asyncio.wait_for = orig
    assert r["result"] == "not_approved"
    assert not os.path.exists(env.remote_gd())


def test_tool_refuses_without_event_call_and_for_non_admin(served):
    env, pub, tool, port, token = served
    pid = _prepare(tool)
    r = json.loads(run(tool.publish_reviewed(pid, __user__=ADMIN, __event_call__=None)))
    assert r["error"] == "approval_unavailable"

    async def yes(ev):
        return True
    for user in ({"id": "u2", "role": "user"}, None, {}):
        r = json.loads(run(tool.publish_reviewed(pid, __user__=user, __event_call__=yes)))
        assert r["error"] == "forbidden"
    tool.valves.allowed_user_ids = "someone-else"
    r = json.loads(run(tool.publish_reviewed(pid, __user__=ADMIN, __event_call__=yes)))
    assert r["error"] == "forbidden"
    assert not os.path.exists(env.remote_gd())


def test_tool_full_flow_confirmed(served):
    env, pub, tool, port, token = served
    st = json.loads(run(tool.publisher_status(__user__=ADMIN)))
    assert st["github"]["login"] == "Nundrian"
    pid = _prepare(tool)
    rv = json.loads(run(tool.review_publish(pid, __user__=ADMIN)))
    assert rv["destination"] == "Nundrian/Demo" and rv["visibility"] == "private"
    statuses = []

    async def emitter(ev):
        statuses.append(ev["data"]["description"])

    async def confirm(ev):
        return True
    r = json.loads(run(tool.publish_reviewed(pid, __user__=ADMIN, __event_emitter__=emitter,
                                             __event_call__=confirm)))
    assert r["published"] and r["verification"]["ok"], r
    v = json.loads(run(tool.verify_publish("demo", __user__=ADMIN)))
    assert v["verification"]["ok"]
    again = json.loads(run(tool.publish_reviewed(pid, __user__=ADMIN, __event_call__=confirm)))
    assert again["result"] == "already_published"
    # compact outputs for small local models
    assert len(json.dumps(rv)) < 6000


def test_unreachable_service(served):
    env, pub, tool, port, token = served
    tool.valves.service_url = "http://127.0.0.1:1"
    r = json.loads(run(tool.publisher_status(__user__=ADMIN)))
    assert r["error"] == "service_unreachable"
