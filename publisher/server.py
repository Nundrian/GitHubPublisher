"""Loopback-only JSON HTTP API used exclusively by the native Open WebUI Tool.

Do NOT register this service as an Open WebUI OpenAPI tool server: the model
would then be able to call the approval endpoints directly. Only the native
Tool, which shows the real browser confirmation, should hold the token."""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import Config
from .github import GitHubError
from .procs import redact
from .service import PublishError, Publisher
from .snapshot import SnapshotError

MAX_BODY = 4096
_PLAN = re.compile(r"^/v1/plans/([A-Za-z0-9-]{1,60})/(review|challenge|publish)$")


def ensure_token(path) -> str:
    path = str(path)
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(32))
    with open(path, encoding="utf-8") as f:
        tok = f.read().strip()
    if len(tok) < 32:
        raise SystemExit("service token file is too short; delete it to regenerate")
    return tok


def make_handler(pub: Publisher, token: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "github-publisher"
        sys_version = ""

        def log_message(self, fmt, *args):   # no request logging to stderr (paths only in audit log)
            pass

        def _send(self, code: int, obj) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _auth(self) -> bool:
            if self.headers.get("Origin") or self.headers.get("Sec-Fetch-Site"):
                self._send(403, {"error": "browser_requests_refused"})
                return False
            got = self.headers.get("Authorization", "")
            if not got.startswith("Bearer ") or not hmac.compare_digest(got[7:].encode(), token.encode()):
                self._send(401, {"error": "unauthorized"})
                return False
            return True

        def _body(self) -> dict | None:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                self._send(413, {"error": "body_too_large"})
                return None
            if n and "application/json" not in (self.headers.get("Content-Type") or ""):
                self._send(415, {"error": "json_required"})
                return None
            try:
                data = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                self._send(400, {"error": "bad_json"})
                return None
            if not isinstance(data, dict):
                self._send(400, {"error": "bad_json"})
                return None
            return data

        def _run(self, fn, *a, **kw):
            try:
                self._send(200, fn(*a, **kw))
            except PublishError as exc:
                code = 409 if exc.code in ("busy", "remote_changed", "name_collision") else 400
                self._send(code, {"error": exc.code, "message": redact(str(exc)), **exc.extra})
            except (SnapshotError, GitHubError) as exc:
                self._send(400, {"error": exc.__class__.__name__, "message": redact(str(exc))})
            except Exception as exc:   # never leak traces or values
                pub.audit("internal_error", kind=exc.__class__.__name__,
                          where=redact("".join(traceback.format_exception_only(type(exc), exc)))[:300])
                self._send(500, {"error": "internal_error", "kind": exc.__class__.__name__})

        def do_GET(self):
            if not self._auth():
                return
            if self.path == "/v1/status":
                return self._run(pub.status)
            m = _PLAN.match(self.path.split("?")[0])
            if m and m.group(2) == "review":
                return self._run(pub.review, m.group(1), detail="detail=1" in self.path)
            self._send(404, {"error": "not_found"})

        def do_POST(self):
            if not self._auth():
                return
            data = self._body()
            if data is None:
                return
            if self.path == "/v1/prepare":
                return self._run(pub.prepare, str(data.get("project", "")))
            if self.path == "/v1/verify":
                return self._run(pub.verify, str(data.get("project", "")))
            m = _PLAN.match(self.path)
            if m and m.group(2) == "challenge":
                return self._run(pub.challenge, m.group(1))
            if m and m.group(2) == "publish":
                return self._run(pub.publish, m.group(1), str(data.get("challenge_id", "")),
                                 str(data.get("nonce", "")), str(data.get("message_sha256", "")))
            self._send(404, {"error": "not_found"})

    return Handler


def serve(cfg: Config, backend=None) -> None:
    token = ensure_token(cfg.token_file)
    pub = Publisher(cfg, backend)
    httpd = ThreadingHTTPServer((cfg.listen_host, cfg.listen_port), make_handler(pub, token))
    httpd.daemon_threads = True
    pub.audit("service_start", host=cfg.listen_host, port=cfg.listen_port)
    print(f"GitHub Publisher listening on http://{cfg.listen_host}:{cfg.listen_port} (loopback only)", flush=True)
    try:
        httpd.serve_forever(poll_interval=1.0)
    except KeyboardInterrupt:
        pass
    finally:
        pub.audit("service_stop")
        httpd.server_close()
        sys.stdout.flush()
