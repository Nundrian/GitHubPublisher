"""GitHub access through the official GitHub CLI (`gh`).

The token never leaves gh: REST calls go through `gh api`, and `git push`
receives credentials from `gh auth git-credential` configured for that single
command only (no global Git configuration is changed)."""

from __future__ import annotations

import json
import re

from .procs import GIT_SAFE, ProcError, git_env, run


class GitHubError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind   # auth | not_found | conflict | network | api | push_rejected


_HTTP_RX = re.compile(r"HTTP (\d{3})")


class GhBackend:
    def __init__(self, gh: str, git: str, git_base_url: str = "https://github.com"):
        if not gh:
            raise GitHubError("auth", "GitHub CLI (gh) not found; install it and run 'gh auth login'")
        self.gh = gh
        self.git = git
        self.git_base_url = git_base_url

    # --- REST -----------------------------------------------------------
    def _api(self, args: list[str], timeout: int = 60, allow_404: bool = False):
        try:
            r = run([self.gh, "api", *args], what="gh api", timeout=timeout, env=git_env())
        except ProcError as exc:
            m = _HTTP_RX.search(exc.detail or "")
            code = int(m.group(1)) if m else None
            if code == 404 and allow_404:
                return None
            if code in (401, 403) or "auth login" in (exc.detail or ""):
                raise GitHubError("auth", "GitHub authentication failed or expired (run 'gh auth login')") from None
            if code == 409 and allow_404:
                return None   # empty repository
            if code == 422:
                raise GitHubError("conflict", "GitHub rejected the request (422)") from None
            if code is None:
                raise GitHubError("network", "GitHub unreachable or gh failed") from None
            raise GitHubError("api", f"GitHub API error HTTP {code}") from None
        text = r.out.decode("utf-8", "replace")
        return json.loads(text) if text.strip() else {}

    def whoami(self) -> dict:
        try:
            r = run([self.gh, "api", "-i", "user"], what="gh api user", timeout=30, env=git_env())
        except ProcError as exc:
            if "HTTP 401" in exc.detail or "auth login" in exc.detail or "not logged" in exc.detail:
                raise GitHubError("auth", "gh is not logged in (run 'gh auth login')") from None
            raise GitHubError("network", "GitHub unreachable or gh failed") from None
        text = r.out.decode("utf-8", "replace").replace("\r\n", "\n")
        head, _, body = text.partition("\n\n")
        scopes = None
        for line in head.splitlines():
            if line.lower().startswith("x-oauth-scopes:"):
                scopes = sorted(s.strip() for s in line.split(":", 1)[1].split(",") if s.strip())
        login = json.loads(body).get("login")
        return {"login": login, "scopes": scopes}

    def get_repo(self, owner: str, repo: str) -> dict | None:
        d = self._api([f"repos/{owner}/{repo}"], allow_404=True)
        if d is None:
            return None
        return {"id": d.get("id"), "private": bool(d.get("private")),
                "visibility": d.get("visibility"), "archived": bool(d.get("archived")),
                "default_branch": d.get("default_branch"), "html_url": d.get("html_url"),
                "owner": (d.get("owner") or {}).get("login")}

    def create_repo(self, owner: str, repo: str, description: str) -> dict:
        d = self._api(["-X", "POST", "user/repos", "-f", f"name={repo}", "-F", "private=true",
                       "-f", f"description={description}", "-F", "auto_init=false",
                       "-F", "has_wiki=false"], timeout=60)
        if (d.get("owner") or {}).get("login", "").lower() != owner.lower():
            raise GitHubError("api", "repository created under an unexpected owner")
        return {"id": d.get("id"), "private": bool(d.get("private")),
                "visibility": d.get("visibility"), "html_url": d.get("html_url")}

    def branch_head(self, owner: str, repo: str, branch: str) -> str | None:
        d = self._api([f"repos/{owner}/{repo}/git/ref/heads/{branch}"], allow_404=True)
        if not d or isinstance(d, list):
            return None
        return (d.get("object") or {}).get("sha")

    def tree(self, owner: str, repo: str, commit_sha: str) -> dict:
        d = self._api([f"repos/{owner}/{repo}/git/trees/{commit_sha}?recursive=1"], timeout=120)
        entries = {e["path"]: {"mode": e["mode"], "sha": e["sha"]}
                   for e in d.get("tree", []) if e.get("type") == "blob"}
        other = [e["path"] for e in d.get("tree", []) if e.get("type") not in ("blob", "tree")]
        return {"entries": entries, "truncated": bool(d.get("truncated")), "other": other}

    def commit_tree_sha(self, owner: str, repo: str, commit_sha: str) -> str | None:
        d = self._api([f"repos/{owner}/{repo}/git/commits/{commit_sha}"], allow_404=True)
        return ((d or {}).get("tree") or {}).get("sha")

    # --- git transport ----------------------------------------------------
    def remote_url(self, owner: str, repo: str) -> str:
        return f"{self.git_base_url}/{owner}/{repo}.git"

    def _cred_args(self) -> list[str]:
        if not self.remote_url("x", "y").startswith("https://"):
            return []
        gh = self.gh.replace("\\", "/")
        return ["-c", f'credential.helper=!"{gh}" auth git-credential']

    def fetch(self, git_dir: str, owner: str, repo: str, branch: str) -> None:
        argv = [self.git, *GIT_SAFE, *self._cred_args(), f"--git-dir={git_dir}", "fetch",
                "--no-tags", "--quiet", self.remote_url(owner, repo),
                f"+refs/heads/{branch}:refs/remotes/origin/{branch}"]
        try:
            run(argv, what="git fetch", timeout=600)
        except ProcError as exc:
            raise GitHubError("network", "git fetch failed: " + exc.detail[:200]) from None

    def push(self, git_dir: str, owner: str, repo: str, commit: str, ref: str) -> None:
        argv = [self.git, *GIT_SAFE, *self._cred_args(), f"--git-dir={git_dir}", "push",
                "--quiet", "--porcelain", self.remote_url(owner, repo), f"{commit}:{ref}"]
        try:
            run(argv, what="git push", timeout=1800)
        except ProcError as exc:
            d = exc.detail
            if "rejected" in d or "non-fast-forward" in d or "fetch first" in d:
                raise GitHubError("push_rejected", "push rejected (remote changed); prepare again") from None
            if "workflow" in d and "scope" in d:
                raise GitHubError("auth", "push refused: token lacks 'workflow' scope "
                                          "(run 'gh auth refresh -s workflow')") from None
            if "Authentication failed" in d or "could not read Username" in d or "403" in d:
                raise GitHubError("auth", "git authentication failed (run 'gh auth login')") from None
            raise GitHubError("network", "git push failed: " + d[:200]) from None
