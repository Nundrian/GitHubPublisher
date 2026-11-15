"""Core operations. Read-only: status, prepare (local staging only), review, verify.
Write: publish (only with a valid, single-use, plan-bound approval challenge)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import stat
import threading
import time
from collections import Counter
from datetime import datetime, timezone

from . import SCHEMA_VERSION, __version__
from .config import Config, Project
from .github import GhBackend, GitHubError
from .policy import Policy
from .procs import GIT_SAFE, ProcError, git_env, run
from .scanner import BLOCK, WARN, Finding, gitleaks_version, run_gitleaks, scan_bytes
from .snapshot import (SnapshotError, check_root, copy_and_hash, file_mode, gitignored,
                       source_like, tracked_in_local_git, verify_tree, walk)

CHALLENGE_TTL_S = 300
PREVIEW = 12


class PublishError(RuntimeError):
    def __init__(self, code: str, message: str, **extra):
        super().__init__(message)
        self.code = code
        self.extra = extra


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _write_json(path: str, obj) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _read_json(path: str, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def _rmtree(path: str) -> None:
    def onerr(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass
    if os.path.isdir(path):
        shutil.rmtree(path, onerror=onerr)


def _mib(n: int) -> str:
    return f"{n / 1048576:.1f} MiB"


class Publisher:
    def __init__(self, cfg: Config, backend=None):
        self.cfg = cfg
        self._backend = backend
        self.lock = threading.Lock()
        self.challenges: dict[str, dict] = {}
        self.root = str(cfg.data_dir)
        for d in ("plans", "state"):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        for d in os.listdir(os.path.join(self.root, "plans")):
            if d.startswith(".tmp-"):          # leftovers of an interrupted prepare
                _rmtree(os.path.join(self.root, "plans", d))

    # ------------------------------------------------------------ helpers
    @property
    def backend(self):
        if self._backend is None:
            self._backend = GhBackend(self.cfg.gh_path, self.cfg.git_path, self.cfg.git_base_url)
        return self._backend

    def audit(self, event: str, **fields) -> None:
        rec = {"ts": _now(), "event": event, **fields}
        with open(os.path.join(self.root, "audit.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

    def _project(self, alias: str) -> Project:
        p = self.cfg.projects.get(str(alias).strip().lower())
        if p is None:
            raise PublishError("unknown_project", "unknown project alias",
                               known=sorted(self.cfg.projects))
        return p

    def _state_path(self) -> str:
        return os.path.join(self.root, "state", "projects.json")

    def _state(self) -> dict:
        return _read_json(self._state_path(), {})

    def _set_state(self, alias: str, **fields) -> None:
        st = self._state()
        st.setdefault(alias, {}).update(fields)
        _write_json(self._state_path(), st)

    def _plan_dir(self, plan_id: str) -> str:
        if not isinstance(plan_id, str) or not all(c.isalnum() or c == "-" for c in plan_id) \
                or len(plan_id) > 60:
            raise PublishError("bad_plan_id", "invalid plan id")
        d = os.path.join(self.root, "plans", plan_id)
        if not os.path.isfile(os.path.join(d, "plan.json")):
            raise PublishError("unknown_plan", "plan not found; prepare again")
        return d

    def _load_plan(self, plan_id: str):
        d = self._plan_dir(plan_id)
        plan = _read_json(os.path.join(d, "plan.json"))
        manifest = _read_json(os.path.join(d, "manifest.json"), [])
        if self._plan_hash(plan, manifest) != plan["plan_hash"]:
            raise PublishError("plan_tampered", "plan or manifest does not match its hash; prepare again")
        return d, plan, manifest

    @staticmethod
    def _plan_hash(plan: dict, manifest: list[dict]) -> str:
        core = {k: plan[k] for k in ("schema", "alias", "owner", "repo", "branch", "visibility",
                                     "action", "base_sha", "target_ref", "commit_message")}
        core["entries"] = [[m["path"], m["mode"], m["blob"], m["sha256"], m["size"]] for m in manifest]
        return hashlib.sha256(_canon(core)).hexdigest()

    # ------------------------------------------------------------ status
    def status(self) -> dict:
        st = self._state()
        gh = {"available": bool(self.cfg.gh_path)}
        try:
            who = self.backend.whoami()
            gh.update(authenticated=True, login=who["login"],
                      login_matches_owner=(who["login"] or "").lower() == self.cfg.owner.lower(),
                      workflow_scope=None if who["scopes"] is None else "workflow" in who["scopes"])
        except GitHubError as exc:
            gh.update(authenticated=False, problem=str(exc))
        projects = []
        for a, p in sorted(self.cfg.projects.items()):
            s = st.get(a, {})
            projects.append({"alias": a, "repo": f"{self.cfg.owner}/{p.repo}", "visibility": "private",
                             "source_present": os.path.isdir(p.source),
                             "last_published_sha": s.get("last_published_sha"),
                             "last_plan_id": s.get("last_plan_id"),
                             "last_verified": s.get("last_verified")})
        return {"service": f"github-publisher {__version__}", "owner": self.cfg.owner, "github": gh,
                "gitleaks": gitleaks_version(self.cfg.gitleaks_path) or "missing",
                "git": bool(self.cfg.git_path), "projects": projects}

    # ------------------------------------------------------------ remote
    def _remote_view(self, p: Project) -> dict:
        """What exists on GitHub now. Never raises; returns {'error': ...} instead."""
        try:
            who = self.backend.whoami()
            if (who["login"] or "").lower() != self.cfg.owner.lower():
                return {"error": "wrong-github-account", "detail": "gh is authenticated as a different account"}
            repo = self.backend.get_repo(self.cfg.owner, p.repo)
            head = self.backend.branch_head(self.cfg.owner, p.repo, p.branch) if repo else None
            return {"scopes": who["scopes"], "repo": repo, "head": head}
        except GitHubError as exc:
            return {"error": exc.kind, "detail": str(exc)}

    def _decide_action(self, p: Project, rv: dict) -> tuple[str, str | None, str | None, str | None]:
        """-> (action, base_sha, target_ref, blocking_reason)"""
        st = self._state().get(p.alias, {})
        repo, head = rv.get("repo"), rv.get("head")
        main_ref = f"refs/heads/{p.branch}"
        if repo is None:
            return "create", None, main_ref, None
        ours = st.get("repo_id") is not None and st.get("repo_id") == repo.get("id")
        if not ours:
            return "none", None, None, ("name-collision: repository already exists and was not created "
                                        "by this publisher; nothing will be overwritten")
        if not repo.get("private"):
            return "none", None, None, "repository is not private; v1 never publishes to public repositories"
        if repo.get("archived"):
            return "none", None, None, "repository is archived"
        if head is None:
            return "initial_push", None, main_ref, None
        if head == st.get("last_published_sha"):
            return "update_ff", head, main_ref, None
        return "update_branch", head, None, None   # target_ref filled with plan id later

    # ------------------------------------------------------------ prepare
    def prepare(self, alias: str) -> dict:
        p = self._project(alias)
        if not self.lock.acquire(blocking=False):
            raise PublishError("busy", "another prepare/publish is running; retry shortly")
        try:
            return self._prepare(p)
        finally:
            self.lock.release()

    def _prepare(self, p: Project) -> dict:
        cfg = self.cfg
        t0 = time.time()
        root = check_root(str(p.source))
        work = os.path.join(self.root, "plans", f".tmp-{secrets.token_hex(6)}")
        tree = os.path.join(work, "tree")
        os.makedirs(tree)
        try:
            policy = Policy(p.exclude, p.include)
            wr = walk(root, policy, cfg.max_files)
            ignored = gitignored(cfg.git_path, root, [c.rel for c in wr.candidates], work) \
                if p.use_gitignore and cfg.git_path else set()
            blocking: list[Finding] = [Finding(r, why, BLOCK, source="walk") for r, why in wr.blocking]
            warnings: list[Finding] = [Finding(r, why, WARN, source="walk") for r, why in wr.warnings]
            excluded_files = list(wr.excluded_files)
            manifest, total = [], 0
            for c in wr.candidates:
                if c.rel in ignored:
                    excluded_files.append((c.rel, "project-gitignore"))
                    continue
                try:
                    entry, head, truncated = copy_and_hash(root, c, tree, cfg.max_file_bytes, cfg.scan_bytes)
                except SnapshotError as exc:
                    blocking.append(Finding(c.rel, str(exc), BLOCK, source="snapshot"))
                    continue
                entry["mode"] = file_mode(c.rel, p.executable)
                fs, is_bin = scan_bytes(c.rel, head, truncated)
                entry["kind"] = "binary" if is_bin else "text"
                for f in fs:
                    (blocking if f.severity == BLOCK else warnings).append(f)
                manifest.append(entry)
                total += entry["size"]
                if entry["size"] > 50 * 1048576:
                    warnings.append(Finding(c.rel, "github-large-file-warning(>50MiB)", WARN))
            if total > cfg.max_total_bytes:
                blocking.append(Finding(".", f"snapshot-too-large({_mib(total)})", BLOCK))
            if not manifest:
                blocking.append(Finding(".", "no-files-staged", BLOCK))

            # Independent scanner (required by default).
            gl = "not-run"
            if cfg.gitleaks_path:
                try:
                    for f in run_gitleaks(cfg.gitleaks_path, tree, work, max(1, cfg.max_file_bytes // 1048576)):
                        blocking.append(f)
                    gl = "ran"
                except ProcError as exc:
                    gl = "failed"
                    blocking.append(Finding(".", "gitleaks-failed", BLOCK, source="gitleaks"))
                    self.audit("gitleaks_failed", alias=p.alias, detail=exc.detail[:200])
            elif cfg.require_gitleaks:
                blocking.append(Finding(".", "gitleaks-not-installed(required)", BLOCK, source="gitleaks"))

            # Human-reviewed, hash-pinned exceptions downgrade specific findings.
            by_path = {m["path"]: m for m in manifest}
            acknowledged = []
            def reviewed(f: Finding) -> bool:
                m = by_path.get(f.path)
                if not m:
                    return False
                for r in p.reviewed:
                    if r.path == f.path and r.sha256 == m["sha256"] and r.rule in ("*", f.rule):
                        return True
                return False
            for lst in (blocking, warnings):
                for f in list(lst):
                    if reviewed(f):
                        lst.remove(f)
                        f.severity = "acknowledged"
                        acknowledged.append(f)

            # Source completeness.
            paths = [m["path"] for m in manifest]
            for req in p.required_paths:
                r = req.strip("/")
                if not any(x == r or x.startswith(r + "/") for x in paths):
                    blocking.append(Finding(r, "required-path-missing(excluded or absent)", BLOCK, source="completeness"))
            tracked = tracked_in_local_git(cfg.git_path, root) if cfg.git_path else None
            tracked_excluded = sorted(tracked - set(paths)) if tracked is not None else []
            src_excluded = sorted(r for r, why in excluded_files
                                  if source_like(r) and why in ("project-exclude", "default-file"))
            if any(x.startswith(".github/workflows/") for x in paths):
                warnings.append(Finding(".github/workflows", "needs-gh-workflow-scope", WARN))
            for nr in wr.nested_repos:
                warnings.append(Finding(nr, "nested-git-repository(content included as plain files, history not)", WARN))
            if ".gitmodules" in paths:
                warnings.append(Finding(".gitmodules", "submodules-not-published(pointers only)", WARN))

            # Remote state and action.
            rv = self._remote_view(p)
            if "error" in rv:
                action, base, target, reason = "unknown", None, None, None
                remote = {"state": "unavailable", "reason": rv["detail"]}
                if rv["error"] == "wrong-github-account":
                    blocking.append(Finding(".", "wrong-github-account", BLOCK, source="remote"))
            else:
                action, base, target, reason = self._decide_action(p, rv)
                remote = {"state": "exists" if rv["repo"] else "absent", "head": rv["head"]}
                if reason:
                    blocking.append(Finding(".", reason, BLOCK, source="remote"))
                scopes = rv.get("scopes")
                if scopes is not None and "workflow" not in scopes and \
                        any(x.startswith(".github/workflows/") for x in paths):
                    blocking.append(Finding(".github/workflows", "gh-token-lacks-workflow-scope"
                                            "(run: gh auth refresh -s workflow)", BLOCK, source="remote"))
            diff = None
            if action in ("update_ff", "update_branch") and base:
                try:
                    rt = self.backend.tree(cfg.owner, p.repo, base)
                    diff = self._diff(rt["entries"], manifest)
                    diff["remote_truncated"] = rt["truncated"]
                except GitHubError as exc:
                    blocking.append(Finding(".", f"cannot-read-remote-tree({exc.kind})", BLOCK, source="remote"))

            plan = {"schema": SCHEMA_VERSION, "alias": p.alias, "owner": cfg.owner, "repo": p.repo,
                    "branch": p.branch, "visibility": "private", "action": action, "base_sha": base,
                    "target_ref": target, "description": p.description,
                    "commit_message": f"Publish reviewed snapshot of {p.alias} ({len(manifest)} files)"}
            if action == "update_branch":
                content = hashlib.sha256(_canon([[m["path"], m["mode"], m["blob"]] for m in manifest])).hexdigest()
                plan["target_ref"] = f"refs/heads/publisher/{content[:12]}"
            plan_hash = self._plan_hash(plan, manifest)
            plan_id = f"{p.alias}-{plan_hash[:12]}"
            if diff is not None and not (diff["added"] or diff["modified"] or diff["removed"]) \
                    and not any(m["mode"] != diff["modes"].get(m["path"], m["mode"]) for m in manifest):
                blocking.append(Finding(".", "no-changes-since-last-publication", BLOCK, source="remote"))
            if diff is not None:
                diff.pop("modes", None)

            status = "blocked" if blocking else ("ready" if action not in ("unknown", "none") else "review_only")
            plan.update({
                "plan_id": plan_id, "plan_hash": plan_hash, "status": status, "created": _now(),
                "service_version": __version__, "remote": remote,
                "totals": {"files": len(manifest), "bytes": total,
                           "binary_files": sum(1 for m in manifest if m["kind"] == "binary"),
                           "excluded_files": len(excluded_files), "excluded_dirs": len(wr.excluded_dirs),
                           "candidates_seen": len(wr.candidates)},
                "top_level": dict(Counter(m["path"].split("/", 1)[0] if "/" in m["path"] else "(root files)"
                                          for m in manifest).most_common()),
                "excluded_summary": dict(Counter(why for _, why in excluded_files + wr.excluded_dirs)),
                "excluded_dirs": [f"{r}/ ({why})" for r, why in wr.excluded_dirs][:200],
                "excluded_source_like": src_excluded[:200], "excluded_source_like_count": len(src_excluded),
                "tracked_but_excluded": tracked_excluded[:200], "tracked_but_excluded_count": len(tracked_excluded),
                "blocking": [f.as_dict() for f in blocking], "warnings": [f.as_dict() for f in warnings],
                "acknowledged": [f.as_dict() for f in acknowledged], "gitleaks": gl, "diff": diff,
                "duration_s": round(time.time() - t0, 1),
            })
            _write_json(os.path.join(work, "manifest.json"), manifest)
            _write_json(os.path.join(work, "excluded.json"),
                        sorted([{"path": r, "reason": w} for r, w in excluded_files] +
                               [{"path": r + "/", "reason": w} for r, w in wr.excluded_dirs],
                               key=lambda x: x["path"]))
            with open(os.path.join(work, "inventory.txt"), "w", encoding="utf-8") as f:
                for m in manifest:
                    f.write(f"{m['size']:>12}  {m['mode']}  {m['path']}\n")
            _rmtree(os.path.join(work, "ignore-oracle.git"))
            if status == "blocked":
                _rmtree(tree)   # never keep extra copies of material that failed review
            _write_json(os.path.join(work, "plan.json"), plan)

            final = os.path.join(self.root, "plans", plan_id)
            if os.path.isdir(final):
                old = _read_json(os.path.join(final, "plan.json"), {})
                if all(old.get(k) == plan[k] for k in ("plan_hash", "status", "blocking", "warnings",
                                                         "acknowledged", "remote")):
                    _rmtree(work)
                    self.audit("prepare_reused", alias=p.alias, plan_id=plan_id)
                    return self.review(plan_id)
                _rmtree(final)
            os.replace(work, final)
            self.audit("prepare", alias=p.alias, plan_id=plan_id, status=status, files=len(manifest),
                       blocking=len(blocking), warnings=len(warnings), action=action)
            return self.review(plan_id)
        except BaseException:
            _rmtree(work)
            raise

    @staticmethod
    def _diff(remote: dict, manifest: list[dict]) -> dict:
        local = {m["path"]: m["blob"] for m in manifest}
        added = sorted(set(local) - set(remote))
        removed = sorted(set(remote) - set(local))
        modified = sorted(p for p in set(local) & set(remote) if local[p] != remote[p]["sha"])
        return {"added": added, "modified": modified, "removed": removed,
                "modes": {p: v["mode"] for p, v in remote.items()}}

    # ------------------------------------------------------------ review
    def review(self, plan_id: str, detail: bool = False) -> dict:
        d, plan, manifest = self._load_plan(plan_id)
        n = 60 if detail else PREVIEW
        out = {k: plan[k] for k in ("plan_id", "status", "action", "branch", "visibility", "created", "gitleaks")}
        out["destination"] = f"{plan['owner']}/{plan['repo']}"
        out["target_ref"] = plan["target_ref"]
        out["snapshot_sha256"] = plan["plan_hash"]
        out["totals"] = plan["totals"]
        out["totals"]["size"] = _mib(plan["totals"]["bytes"])
        out["remote"] = plan["remote"]
        out["blocking"] = plan["blocking"][:n]
        out["blocking_count"] = len(plan["blocking"])
        out["warnings"] = plan["warnings"][:n]
        out["warning_count"] = len(plan["warnings"])
        out["acknowledged_count"] = len(plan["acknowledged"])
        out["excluded_summary"] = plan["excluded_summary"]
        out["excluded_source_like"] = {"count": plan["excluded_source_like_count"],
                                       "sample": plan["excluded_source_like"][:n]}
        out["tracked_in_local_git_but_excluded"] = {"count": plan["tracked_but_excluded_count"],
                                                    "sample": plan["tracked_but_excluded"][:n]}
        if detail:
            out["top_level"] = plan["top_level"]
            out["excluded_dirs"] = plan["excluded_dirs"][:n]
        if plan.get("diff"):
            df = plan["diff"]
            out["diff"] = {k: {"count": len(df[k]), "sample": df[k][:n]} for k in ("added", "modified", "removed")}
        out["full_manifest"] = os.path.join(d, "manifest.json")
        out["full_inventory"] = os.path.join(d, "inventory.txt")
        pub = _read_json(os.path.join(d, "publication.json"))
        if pub:
            out["publication"] = {k: pub.get(k) for k in ("state", "commit", "pushed_ref", "verified", "error")}
        out["next"] = {"ready": "call publish_reviewed with this plan_id; a confirmation dialog will be shown",
                       "blocked": "fix the blocking items (exclude, remove, or have the admin add a reviewed "
                                  "hash-pinned exception), then prepare again",
                       "review_only": "GitHub state unavailable; fix gh login/network and prepare again",
                       }.get(plan["status"], "")
        return out

    def suggest_reviewed(self, plan_id: str, rule_prefix: str = "") -> list[dict]:
        """Admin helper: hash-pinned 'reviewed' entries for the plan's blocking findings.
        Printing these does NOT approve anything; the admin must inspect each file and
        paste the chosen entries into the config."""
        d, plan, manifest = self._load_plan(plan_id)
        by_path = {m["path"]: m["sha256"] for m in manifest}
        out = []
        for b in plan["blocking"]:
            if b["path"] in by_path and b["rule"].startswith(rule_prefix):
                out.append({"path": b["path"], "sha256": by_path[b["path"]], "rule": b["rule"],
                            "note": "REVIEWED BY <name> ON <date>: <why this is safe>"})
        return out

    # ------------------------------------------------------------ approval
    def _expectation_ok(self, plan: dict, rv: dict, pub: dict | None) -> str | None:
        """None if the remote is still exactly what the plan was prepared against
        (or a resumable state left by this same plan)."""
        if "error" in rv:
            return f"GitHub unavailable: {rv['detail']}"
        repo, head = rv["repo"], rv["head"]
        st = self._state().get(plan["alias"], {})
        if repo is not None and not repo.get("private"):
            return "repository is not private"
        a = plan["action"]
        commit = (pub or {}).get("commit")
        if a == "create":
            if repo is None:
                return None
            if pub and pub.get("repo_id") == repo.get("id") and head in (None, commit):
                return None   # resume after partial failure of this very plan
            return "repository now exists; prepare again"
        if repo is None or repo.get("id") != st.get("repo_id"):
            return "repository identity changed; prepare again"
        if a == "initial_push":
            return None if head in (None, commit) else "remote branch changed; prepare again"
        if a == "update_ff":
            return None if head in (plan["base_sha"], commit) else "remote branch moved; prepare again"
        if a == "update_branch":
            return None
        return f"plan action {a} cannot be published"

    def _preflight(self, plan_id: str):
        d, plan, manifest = self._load_plan(plan_id)
        if plan["status"] != "ready":
            raise PublishError("not_ready", f"plan status is {plan['status']}; nothing can be published")
        problems = verify_tree(os.path.join(d, "tree"), manifest)
        if problems:
            self.audit("snapshot_integrity_failed", plan_id=plan_id, problems=len(problems))
            raise PublishError("snapshot_tampered", "staged snapshot no longer matches the reviewed manifest",
                               sample=problems[:5])
        p = self._project(plan["alias"])
        if p.repo != plan["repo"] or self.cfg.owner != plan["owner"] or plan["repo"].lower() in self.cfg.protected_repos:
            raise PublishError("config_changed", "destination no longer matches configuration")
        pub = _read_json(os.path.join(d, "publication.json"))
        rv = self._remote_view(p)
        if rv.get("error") == "wrong-github-account":
            raise PublishError("wrong_account", "gh is authenticated as a different account")
        if "error" not in rv and rv.get("scopes") is not None and "workflow" not in rv["scopes"] and \
                any(m["path"].startswith(".github/workflows/") for m in manifest):
            raise PublishError("missing_scope", "gh token lacks 'workflow' scope (gh auth refresh -s workflow)")
        why = self._expectation_ok(plan, rv, pub)
        if why:
            raise PublishError("remote_changed", why)
        return d, plan, manifest, p, rv, pub

    @staticmethod
    def dialog_text(plan: dict) -> tuple[str, str]:
        act = {"create": "Create a NEW private repository and push the snapshot to `{b}`",
               "initial_push": "Push the snapshot to `{b}` of the existing (empty) repository created by this publisher",
               "update_ff": "Add one commit on top of `{b}` (fast-forward, no force)",
               "update_branch": "Push to a NEW branch `{t}` (remote `{b}` changed; nothing overwritten)",
               }[plan["action"]].format(b=plan["branch"], t=(plan["target_ref"] or "").replace("refs/heads/", ""))
        t = plan["totals"]
        msg = (f"**Approve publication to GitHub?**\n\n"
               f"| | |\n|---|---|\n"
               f"| Repository | `{plan['owner']}/{plan['repo']}` — **PRIVATE** |\n"
               f"| Action | {act} |\n"
               f"| Files | {t['files']} files, {_mib(t['bytes'])} |\n"
               f"| Snapshot SHA-256 | `{plan['plan_hash']}` |\n"
               f"| Plan | `{plan['plan_id']}` |\n"
               f"| Warnings | {len(plan['warnings'])} (see review) |\n\n"
               f"Only these exact reviewed bytes will be pushed. No force-push, deletion or visibility change. "
               f"**Cancel = nothing happens.**")
        return "GitHub Publisher — approval required", msg

    def challenge(self, plan_id: str) -> dict:
        d, plan, manifest, p, rv, pub = self._preflight(plan_id)
        if pub and pub.get("state") == "verified":
            return {"already_published": True, "commit": pub.get("commit")}
        title, message = self.dialog_text(plan)
        cid = secrets.token_urlsafe(12)
        nonce = secrets.token_urlsafe(24)
        now = time.time()
        self.challenges = {k: v for k, v in self.challenges.items()
                           if v["expires"] > now and v["plan_id"] != plan_id}
        self.challenges[cid] = {"plan_id": plan_id, "plan_hash": plan["plan_hash"],
                                "nonce": hashlib.sha256(nonce.encode()).hexdigest(),
                                "message_sha256": hashlib.sha256(message.encode()).hexdigest(),
                                "expires": now + CHALLENGE_TTL_S}
        self.audit("challenge_issued", plan_id=plan_id)
        return {"challenge_id": cid, "nonce": nonce, "title": title, "message": message,
                "expires_in_s": CHALLENGE_TTL_S}

    def _consume_challenge(self, plan_id, challenge_id, nonce, message_sha256) -> dict:
        ch = self.challenges.pop(str(challenge_id), None)   # single use, even on failure
        if ch is None or ch["expires"] < time.time():
            raise PublishError("approval_invalid", "approval missing, expired or already used")
        ok = (ch["plan_id"] == plan_id and
              hmac.compare_digest(ch["nonce"], hashlib.sha256(str(nonce).encode()).hexdigest()) and
              hmac.compare_digest(ch["message_sha256"], str(message_sha256)))
        if not ok:
            raise PublishError("approval_invalid", "approval does not match this plan")
        return ch

    # ------------------------------------------------------------ publish
    def publish(self, plan_id: str, challenge_id: str, nonce: str, message_sha256: str) -> dict:
        if not self.lock.acquire(blocking=False):
            raise PublishError("busy", "another prepare/publish is running; retry shortly")
        try:
            ch = self._consume_challenge(plan_id, challenge_id, nonce, message_sha256)
            d, plan, manifest, p, rv, pub = self._preflight(plan_id)   # re-check immediately before writing
            if ch["plan_hash"] != plan["plan_hash"]:
                raise PublishError("approval_invalid", "plan changed after approval")
            self.audit("publish_approved", plan_id=plan_id, repo=f"{plan['owner']}/{plan['repo']}",
                       action=plan["action"])
            return self._publish(d, plan, manifest, p, rv, pub or {})
        finally:
            self.lock.release()

    def _git(self, gd: str, *args, input=None, env_extra=None, what="git"):
        env = git_env(env_extra or {})
        return run([self.cfg.git_path, *GIT_SAFE, f"--git-dir={gd}", *args], what=what,
                   input=input, env=env, timeout=600)

    def _build_commit(self, d: str, plan: dict, manifest: list[dict], p: Project) -> str:
        gd = os.path.join(d, "git")
        if not os.path.isdir(gd):
            run([self.cfg.git_path, "init", "-q", "--bare", gd], what="git init", env=git_env())
        tree_root = os.path.join(d, "tree")
        parent = []
        if plan["base_sha"]:
            self.backend.fetch(gd, plan["owner"], plan["repo"], plan["branch"])
            got = self._git(gd, "rev-parse", f"refs/remotes/origin/{plan['branch']}").out.decode().strip()
            if got != plan["base_sha"]:
                raise PublishError("remote_changed", "remote branch moved; prepare again")
            parent = ["-p", plan["base_sha"]]
        paths = "\n".join(os.path.join(tree_root, *m["path"].split("/")) for m in manifest) + "\n"
        shas = self._git(gd, "hash-object", "-w", "--no-filters", "--stdin-paths",
                         input=paths.encode("utf-8"), what="git hash-object").out.decode().split()
        if shas != [m["blob"] for m in manifest]:
            raise PublishError("snapshot_tampered", "blob hashes differ from reviewed manifest")
        index = os.path.join(d, "index")
        if os.path.exists(index):
            os.remove(index)
        info = b"".join(f"{m['mode']} {m['blob']}\t{m['path']}".encode("utf-8") + b"\0" for m in manifest)
        env_i = {"GIT_INDEX_FILE": index}
        self._git(gd, "update-index", "--add", "-z", "--index-info", input=info, env_extra=env_i,
                  what="git update-index")
        tree_sha = self._git(gd, "write-tree", env_extra=env_i, what="git write-tree").out.decode().strip()
        ident = {"GIT_AUTHOR_NAME": self.cfg.commit_name, "GIT_AUTHOR_EMAIL": self.cfg.commit_email,
                 "GIT_COMMITTER_NAME": self.cfg.commit_name, "GIT_COMMITTER_EMAIL": self.cfg.commit_email}
        msg = plan["commit_message"] + f"\n\nSnapshot-SHA256: {plan['plan_hash']}\nPlan: {plan['plan_id']}\n"
        commit = self._git(gd, "commit-tree", tree_sha, *parent, "-m", msg, env_extra=ident,
                           what="git commit-tree").out.decode().strip()
        ls = self._git(gd, "ls-tree", "-r", "-z", "--full-tree", commit, what="git ls-tree").out
        got = {}
        for rec in ls.split(b"\0"):
            if rec:
                meta, path = rec.split(b"\t", 1)
                mode, _typ, sha = meta.decode().split()
                got[path.decode("utf-8")] = (mode, sha)
        want = {m["path"]: (m["mode"], m["blob"]) for m in manifest}
        if got != want:
            raise PublishError("build_mismatch", "built commit tree differs from manifest")
        return commit

    def _publish(self, d, plan, manifest, p, rv, pub) -> dict:
        pubf = os.path.join(d, "publication.json")
        def save(**kw):
            pub.update(kw, updated=_now())
            _write_json(pubf, pub)
        owner, repo = plan["owner"], plan["repo"]
        try:
            commit = pub.get("commit") or self._build_commit(d, plan, manifest, p)
            save(state="commit_built", commit=commit)
            if rv["repo"] is None:
                try:
                    created = self.backend.create_repo(owner, repo, plan.get("description", ""))
                except GitHubError as exc:
                    if exc.kind == "conflict":
                        raise PublishError("name_collision", "repository name already taken; nothing written") from None
                    # The response may have been lost after GitHub created the repository.
                    # Adopt it only if it is private and completely empty (nothing to overwrite).
                    probe = self.backend.get_repo(owner, repo)
                    if probe and probe.get("private") and \
                            self.backend.branch_head(owner, repo, plan["branch"]) is None:
                        created = probe
                        self.audit("repo_create_response_lost_adopted_empty", plan_id=plan["plan_id"])
                    else:
                        raise
                save(state="repo_created", repo_id=created["id"])
                self._set_state(p.alias, repo=repo, repo_id=created["id"], created_by_publisher=True,
                                created_plan=plan["plan_id"], created_at=_now())
                self.audit("repo_created", plan_id=plan["plan_id"], repo=f"{owner}/{repo}")
                rv = {"repo": self.backend.get_repo(owner, repo), "head": None}
            elif plan["action"] == "create":
                save(state="resuming")
            if not rv["repo"] or not rv["repo"].get("private"):
                save(state="halted_not_private")
                raise PublishError("not_private", "repository is not private; push not attempted")
            ref = plan["target_ref"]
            if rv.get("head") != commit:
                self.backend.push(os.path.join(d, "git"), owner, repo, commit, ref)
            save(state="pushed", pushed_ref=ref)
            self.audit("pushed", plan_id=plan["plan_id"], repo=f"{owner}/{repo}", ref=ref, commit=commit)
        except (GitHubError, ProcError, PublishError) as exc:
            code = getattr(exc, "kind", None) or getattr(exc, "code", "error")
            save(failed=True, error=f"{code}: {exc}"[:300])
            self.audit("publish_failed", plan_id=plan["plan_id"], error=str(code))
            raise PublishError("publish_failed", str(exc), stage=pub.get("state"),
                               resumable=True, hint="fix the cause, then call publish_reviewed again "
                                                    "for the same plan_id (a new approval is required)") from None
        if ref == f"refs/heads/{plan['branch']}":
            self._set_state(p.alias, last_published_sha=commit, last_plan_id=plan["plan_id"],
                            last_published_at=_now())
        result = self._verify_plan(d, plan, manifest, commit, ref)
        save(state="verified" if result["ok"] else "pushed_unverified", verified=result["ok"], failed=False, error=None)
        return {"published": True, "repository": f"{owner}/{repo}", "ref": ref, "commit": commit,
                "verification": result}

    # ------------------------------------------------------------ verify
    def _verify_plan(self, d, plan, manifest, commit, ref) -> dict:
        owner, repo = plan["owner"], plan["repo"]
        checks, ok = {}, True
        try:
            r = self.backend.get_repo(owner, repo)
            checks["private"] = bool(r and r.get("private"))
            head = self.backend.branch_head(owner, repo, ref.replace("refs/heads/", ""))
            checks["branch_head_matches"] = head == commit
            t = self.backend.tree(owner, repo, commit)
            want = {m["path"]: (m["mode"], m["blob"]) for m in manifest}
            got = {k: (v["mode"], v["sha"]) for k, v in t["entries"].items()}
            checks["tree_truncated_by_api"] = t["truncated"]
            checks["remote_files"] = len(got)
            checks["missing_on_remote"] = sorted(set(want) - set(got))[:10]
            checks["unexpected_on_remote"] = sorted(set(got) - set(want))[:10]
            checks["content_mismatch"] = sorted(k for k in set(want) & set(got) if want[k] != got[k])[:10]
            checks["non_blob_entries"] = t["other"][:10]
            ok = (checks["private"] and checks["branch_head_matches"] and not t["truncated"] and
                  not checks["missing_on_remote"] and not checks["unexpected_on_remote"] and
                  not checks["content_mismatch"] and not checks["non_blob_entries"])
        except GitHubError as exc:
            checks["error"] = str(exc)
            ok = False
        self.audit("verify", plan_id=plan["plan_id"], ok=ok)
        if ok and ref == f"refs/heads/{plan['branch']}":
            self._set_state(plan["alias"], last_verified=_now())
        return {"ok": ok, **checks}

    def verify(self, alias: str) -> dict:
        p = self._project(alias)
        st = self._state().get(p.alias, {})
        pid = st.get("last_plan_id")
        if not pid:
            # maybe a branch publication or a partial failure: report what we know
            return {"alias": p.alias, "published": False, "state": {k: st.get(k) for k in ("repo_id", "created_plan")},
                    "remote": {k: v for k, v in self._remote_view(p).items() if k != "scopes"}}
        d, plan, manifest = self._load_plan(pid)
        res = self._verify_plan(d, plan, manifest, st["last_published_sha"], f"refs/heads/{plan['branch']}")
        return {"alias": p.alias, "repository": f"{plan['owner']}/{plan['repo']}", "plan_id": pid,
                "commit": st["last_published_sha"], "verification": res}
