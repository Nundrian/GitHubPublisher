"""Administrator configuration (JSON). Nothing here is ever model-controlled."""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,100}$")

# Repositories this publisher must never write to, whatever the config says.
ALWAYS_PROTECTED = {"safe-route-regional-data"}


class ConfigError(ValueError):
    pass


@dataclass
class ReviewedException:
    """A human-reviewed, hash-pinned exception for one scanner finding."""
    path: str
    sha256: str
    rule: str = "*"
    note: str = ""


@dataclass
class Project:
    alias: str
    source: Path
    repo: str
    description: str = ""
    branch: str = "main"
    use_gitignore: bool = True
    exclude: list[str] = field(default_factory=list)
    include: list[str] = field(default_factory=list)
    required_paths: list[str] = field(default_factory=list)
    executable: list[str] = field(default_factory=list)
    reviewed: list[ReviewedException] = field(default_factory=list)


@dataclass
class Config:
    path: Path
    listen_host: str
    listen_port: int
    data_dir: Path
    token_file: Path
    owner: str
    git_path: str
    gh_path: str
    gitleaks_path: str | None
    require_gitleaks: bool
    commit_name: str
    commit_email: str
    git_base_url: str          # https://github.com (tests may point at file://)
    max_file_bytes: int
    max_total_bytes: int
    max_files: int
    scan_bytes: int
    protected_repos: set[str]
    projects: dict[str, Project]
    tool_timeout_s: int = 900


def _expand(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))


def _resolve_exe(value: str | None, name: str) -> str | None:
    if value:
        v = _expand(value)
        if os.path.isabs(v):
            return v if os.path.isfile(v) else None
        found = shutil.which(v)
        return os.path.abspath(found) if found else None
    found = shutil.which(name)
    return os.path.abspath(found) if found else None


def load_config(path: str | os.PathLike) -> Config:
    cpath = Path(path).resolve()
    try:
        raw = json.loads(cpath.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read config {cpath.name}: {exc.__class__.__name__}") from None
    if raw.get("schema") != 1:
        raise ConfigError("config schema must be 1")

    host = raw.get("listen_host", "127.0.0.1")
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ConfigError("listen_host must be loopback (127.0.0.1); LAN exposure is not supported")
    port = int(raw.get("listen_port", 8766))
    if not 1024 <= port <= 65535:
        raise ConfigError("listen_port out of range")

    data_dir = Path(_expand(raw.get("data_dir", "~/.github-publisher"))).resolve()
    token_file = Path(_expand(raw.get("token_file", str(data_dir / "service-token.txt")))).resolve()

    gh = raw.get("github", {})
    owner = gh.get("owner", "")
    if not OWNER_RE.match(owner):
        raise ConfigError("github.owner invalid")

    sc = raw.get("scanner", {})
    gitleaks = _resolve_exe(sc.get("gitleaks_path"), "gitleaks")

    protected = set(ALWAYS_PROTECTED) | {r.lower() for r in raw.get("protected_repos", [])}

    projects: dict[str, Project] = {}
    seen_repos: set[str] = set()
    for alias, p in (raw.get("projects") or {}).items():
        if not ALIAS_RE.match(alias):
            raise ConfigError(f"invalid project alias {alias!r}")
        repo = p.get("repo", "")
        if not REPO_RE.match(repo) or repo in (".", ".."):
            raise ConfigError(f"{alias}: invalid repo name")
        if repo.lower() in protected:
            raise ConfigError(f"{alias}: repository {repo} is protected and may not be a publish target")
        if repo.lower() in seen_repos:
            raise ConfigError(f"{alias}: repository {repo} is used by another project")
        seen_repos.add(repo.lower())
        branch = p.get("branch", "main")
        if not BRANCH_RE.match(branch) or ".." in branch:
            raise ConfigError(f"{alias}: invalid branch")
        src = Path(_expand(p.get("source", "")))
        if not src.is_absolute():
            raise ConfigError(f"{alias}: source must be an absolute path")
        reviewed = []
        for r in p.get("reviewed", []):
            if not re.fullmatch(r"[0-9a-f]{64}", r.get("sha256", "")):
                raise ConfigError(f"{alias}: reviewed entry needs full sha256")
            reviewed.append(ReviewedException(r["path"].replace("\\", "/"), r["sha256"],
                                              r.get("rule", "*"), r.get("note", "")))
        projects[alias] = Project(
            alias=alias, source=src, repo=repo,
            description=str(p.get("description", ""))[:300],
            branch=branch,
            use_gitignore=bool(p.get("use_gitignore", True)),
            exclude=list(p.get("exclude", [])),
            include=list(p.get("include", [])),
            required_paths=list(p.get("required_paths", [])),
            executable=list(p.get("executable", [])),
            reviewed=reviewed,
        )

    return Config(
        path=cpath,
        listen_host="127.0.0.1" if host == "localhost" else host,
        listen_port=port,
        data_dir=data_dir,
        token_file=token_file,
        owner=owner,
        git_path=_resolve_exe(gh.get("git_path"), "git") or "",
        gh_path=_resolve_exe(gh.get("gh_path"), "gh") or "",
        gitleaks_path=gitleaks,
        require_gitleaks=bool(sc.get("require_gitleaks", True)),
        commit_name=gh.get("commit_name", owner),
        commit_email=gh.get("commit_email", f"{owner}@users.noreply.github.com"),
        git_base_url=gh.get("git_base_url", "https://github.com").rstrip("/"),
        max_file_bytes=int(sc.get("max_file_bytes", 25 * 1024 * 1024)),
        max_total_bytes=int(sc.get("max_total_bytes", 900 * 1024 * 1024)),
        max_files=int(sc.get("max_files", 30000)),
        scan_bytes=int(sc.get("scan_bytes", 8 * 1024 * 1024)),
        protected_repos=protected,
        projects=projects,
        tool_timeout_s=int(raw.get("tool_timeout_s", 900)),
    )
