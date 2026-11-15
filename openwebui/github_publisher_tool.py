"""
title: GitHub Publisher
author: Nundrian (generated with Claude)
description: Prepare, review, publish (with real browser confirmation) and verify allowlisted local projects to private GitHub repositories via the loopback GitHub Publisher service.
required_open_webui_version: 0.12.5
version: 1.0.0
licence: MIT
"""

import asyncio
import hashlib
import json
import urllib.error
import urllib.request

from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        service_url: str = Field(
            default="http://host.docker.internal:8766",
            description="GitHub Publisher service URL (loopback service on the Windows host).",
        )
        service_token: str = Field(
            default="",
            description="Service token from 'show-token'. Not a GitHub credential.",
            json_schema_extra={"input": {"type": "password"}},
        )
        allowed_user_ids: str = Field(
            default="",
            description="Comma-separated Open WebUI user ids allowed to use this tool (admins only if empty).",
        )
        confirm_timeout_s: int = Field(default=180, description="Seconds to wait for the approval dialog.")
        request_timeout_s: int = Field(default=900, description="Timeout for prepare/publish requests.")
        pass

    def __init__(self):
        self.valves = self.Valves()
        self.citation = False

    # ---------------------------------------------------------------- helpers
    def _authorised(self, user) -> bool:
        user = user or {}
        allowed = [u.strip() for u in self.valves.allowed_user_ids.split(",") if u.strip()]
        if allowed:
            return user.get("id") in allowed and user.get("role") == "admin"
        return user.get("role") == "admin"

    def _call_sync(self, method: str, path: str, body):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            self.valves.service_url.rstrip("/") + path, data=data, method=method,
            headers={"Authorization": f"Bearer {self.valves.service_token}",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.valves.request_timeout_s) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode())
            except Exception:
                return {"error": f"http_{e.code}"}
        except Exception as e:
            return {"error": "service_unreachable", "message": e.__class__.__name__}

    async def _call(self, method, path, body=None):
        return await asyncio.to_thread(self._call_sync, method, path, body)

    @staticmethod
    async def _status(emitter, text, done=False):
        if emitter:
            await emitter({"type": "status", "data": {"description": text, "done": done, "hidden": False}})

    @staticmethod
    def _out(obj) -> str:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def _guard(self, user):
        if not self.valves.service_token:
            return self._out({"error": "not_configured", "message": "admin must set the service_token valve"})
        if not self._authorised(user):
            return self._out({"error": "forbidden", "message": "only the configured administrator may use this tool"})
        return None

    # ---------------------------------------------------------------- tools
    async def publisher_status(self, __user__: dict = None, __event_emitter__=None) -> str:
        """
        Read-only. List publishable project aliases, their GitHub destination, last published commit and GitHub login state.
        """
        if (g := self._guard(__user__)):
            return g
        return self._out(await self._call("GET", "/v1/status"))

    async def prepare_publish(self, project: str, __user__: dict = None, __event_emitter__=None) -> str:
        """
        Read-only for GitHub and for the source folder. Scan one project, stage an immutable snapshot, run secret/privacy checks and return a compact review with a plan_id. Never publishes.
        :param project: Project alias exactly as listed by publisher_status, e.g. "uehl" or "saferoute".
        """
        if (g := self._guard(__user__)):
            return g
        await self._status(__event_emitter__, f"Preparing snapshot of {project}…")
        r = await self._call("POST", "/v1/prepare", {"project": project})
        await self._status(__event_emitter__, "Snapshot prepared" if "plan_id" in r else "Prepare failed", True)
        return self._out(r)

    async def review_publish(self, plan_id: str, __user__: dict = None) -> str:
        """
        Read-only. Detailed review of a prepared plan: destination, totals, blocking items, warnings, exclusions and remote diff (bounded lists; full manifest stays on disk).
        :param plan_id: The plan_id returned by prepare_publish.
        """
        if (g := self._guard(__user__)):
            return g
        return self._out(await self._call("GET", f"/v1/plans/{plan_id}/review?detail=1"))

    async def publish_reviewed(self, plan_id: str, __user__: dict = None, __event_emitter__=None,
                               __event_call__=None) -> str:
        """
        WRITE. Ask the human (browser dialog) to approve publishing this exact reviewed plan to its private GitHub repository; publishes only if they click Confirm. The model cannot approve on the user's behalf.
        :param plan_id: The plan_id returned by prepare_publish.
        """
        if (g := self._guard(__user__)):
            return g
        if __event_call__ is None:
            return self._out({"error": "approval_unavailable",
                              "message": "no interactive browser session; nothing was published"})
        ch = await self._call("POST", f"/v1/plans/{plan_id}/challenge", {})
        if ch.get("already_published"):
            return self._out({"result": "already_published", "commit": ch.get("commit")})
        if "challenge_id" not in ch:
            return self._out(ch)
        try:
            answer = await asyncio.wait_for(
                __event_call__({"type": "confirmation",
                                "data": {"title": ch["title"], "message": ch["message"]}}),
                timeout=max(10, int(self.valves.confirm_timeout_s)))
        except asyncio.TimeoutError:
            answer = None
        except Exception:
            answer = None
        if answer is not True:   # cancel, timeout, disconnect ({'error':...}) or anything else = NO
            await self._status(__event_emitter__, "Publication not approved; nothing was published", True)
            return self._out({"result": "not_approved", "message": "the user did not confirm; nothing was published"})
        await self._status(__event_emitter__, "Approved by user; publishing…")
        r = await self._call("POST", f"/v1/plans/{plan_id}/publish", {
            "challenge_id": ch["challenge_id"], "nonce": ch["nonce"],
            "message_sha256": hashlib.sha256(ch["message"].encode()).hexdigest()})
        await self._status(__event_emitter__, "Published and verified" if (r.get("verification") or {}).get("ok")
                           else "Publish finished with problems", True)
        return self._out(r)

    async def verify_publish(self, project: str, __user__: dict = None) -> str:
        """
        Read-only. Independently check the GitHub repository (privacy, branch commit, full file tree) against the last published snapshot.
        :param project: Project alias, e.g. "uehl" or "saferoute".
        """
        if (g := self._guard(__user__)):
            return g
        return self._out(await self._call("POST", "/v1/verify", {"project": project}))
