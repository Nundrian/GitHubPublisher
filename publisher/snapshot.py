"""Read-only walk of an allowlisted source root and creation of an isolated,
hash-anchored snapshot. The source tree is only ever opened for reading."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass, field

from .policy import Policy, SOURCE_LIKE, match
from .procs import GIT_SAFE, ProcError, git_env, run

IS_WIN = sys.platform == "win32"
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
CHUNK = 1024 * 1024


class SnapshotError(RuntimeError):
    pass


@dataclass
class Candidate:
    rel: str
    size: int
    mtime_ns: int


@dataclass
class WalkResult:
    candidates: list[Candidate] = field(default_factory=list)
    excluded_dirs: list[tuple[str, str]] = field(default_factory=list)
    excluded_files: list[tuple[str, str]] = field(default_factory=list)
    blocking: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)
    nested_repos: list[str] = field(default_factory=list)


def _long(p: str) -> str:
    if IS_WIN and len(p) > 240 and not p.startswith("\\\\?\\"):
        return "\\\\?\\" + os.path.abspath(p)
    return p


def _is_link(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & REPARSE)


def check_root(source: str) -> str:
    """Canonical, link-free project root or SnapshotError."""
    if IS_WIN and (source.startswith("\\\\") or source.startswith("//")):
        raise SnapshotError("UNC/device paths are not allowed as project roots")
    try:
        st = os.lstat(source)
    except OSError:
        raise SnapshotError("project source folder not found") from None
    if _is_link(st):
        raise SnapshotError("project root is a symlink/junction; configure its real path")
    if not stat.S_ISDIR(st.st_mode):
        raise SnapshotError("project source is not a directory")
    real = os.path.realpath(source)
    if os.path.normcase(real) != os.path.normcase(os.path.abspath(source)):
        raise SnapshotError("project root resolves elsewhere (link in path); configure the real path")
    return real


def walk(root: str, policy: Policy, max_files: int) -> WalkResult:
    res = WalkResult()
    seen_lower: dict[str, str] = {}
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        abs_dir = os.path.join(root, rel_dir) if rel_dir else root
        try:
            with os.scandir(_long(abs_dir)) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            res.blocking.append((rel_dir or ".", f"unreadable-directory({exc.__class__.__name__})"))
            continue
        if any(e.name.lower() == ".git" for e in entries) and rel_dir:
            res.nested_repos.append(rel_dir)
        for e in entries:
            rel = f"{rel_dir}/{e.name}" if rel_dir else e.name
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as exc:
                res.blocking.append((rel, f"unreadable({exc.__class__.__name__})"))
                continue
            is_dir = stat.S_ISDIR(st.st_mode) and not _is_link(st)
            # Exclusion first: links inside excluded areas are irrelevant.
            if is_dir:
                reason = policy.dir_reason(rel)
                if reason:
                    res.excluded_dirs.append((rel, reason))
                    continue
            elif not _is_link(st):
                reason = policy.file_reason(rel)
                if reason:
                    res.excluded_files.append((rel, reason))
                    continue
            problem = policy.name_problem(e.name)
            if problem:
                # Cannot be read faithfully on Windows (e.g. 'NUL' opens the null device).
                res.excluded_files.append((rel, problem))
                res.warnings.append((rel, problem))
                continue
            if _is_link(st):
                res.blocking.append((rel, "symlink-or-junction(not followed)"))
                continue
            low = rel.lower()
            if low in seen_lower:
                res.blocking.append((rel, "case-insensitive-path-collision"))
                continue
            seen_lower[low] = rel
            if is_dir:
                stack.append(rel)
            elif stat.S_ISREG(st.st_mode):
                res.candidates.append(Candidate(rel, st.st_size, st.st_mtime_ns))
                if len(res.candidates) > max_files:
                    raise SnapshotError(f"more than {max_files} candidate files; tighten exclusions")
            else:
                res.blocking.append((rel, "special-file"))
    res.candidates.sort(key=lambda c: c.rel)
    return res


def gitignored(git: str, root: str, rels: list[str], work_dir: str) -> set[str]:
    """Ask Git itself which paths the project's own .gitignore files exclude.
    Uses a private, empty git-dir, so the project's .git config/hooks are never used."""
    if not rels:
        return set()
    gd = os.path.join(work_dir, "ignore-oracle.git")
    if not os.path.isdir(gd):
        run([git, "init", "-q", "--bare", gd], what="git init (ignore oracle)", timeout=30)
    argv = [git, *GIT_SAFE, "-c", f"core.ignorecase={'true' if IS_WIN else 'false'}",
            "-c", "core.excludesFile=", f"--git-dir={gd}", f"--work-tree={root}",
            "check-ignore", "--no-index", "-z", "--stdin"]
    data = b"\0".join(r.encode("utf-8") for r in rels) + b"\0"
    r = run(argv, what="git check-ignore", input=data, timeout=300, check=False, cwd=root)
    if r.code not in (0, 1):
        raise ProcError("git check-ignore", r.code, r.err)
    return {p.decode("utf-8") for p in r.out.split(b"\0") if p}


def git_blob_sha(size: int) -> "hashlib._Hash":
    h = hashlib.sha1()
    h.update(b"blob %d\0" % size)
    return h


def copy_and_hash(root: str, cand: Candidate, dest_root: str, max_bytes: int, scan_bytes: int):
    """Copy one file without following links, hashing what was actually read.
    Returns (entry, head_bytes, truncated) or raises SnapshotError(reason)."""
    src = os.path.join(root, *cand.rel.split("/"))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(_long(src), flags)
    except OSError as exc:
        raise SnapshotError(f"unreadable({exc.__class__.__name__})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SnapshotError("not-a-regular-file")
        if st.st_size != cand.size:
            raise SnapshotError("changed-during-snapshot")
        if st.st_size > max_bytes:
            raise SnapshotError(f"oversized({st.st_size} bytes)")
        dest = os.path.join(dest_root, *cand.rel.split("/"))
        os.makedirs(_long(os.path.dirname(dest)), exist_ok=True)
        sha = hashlib.sha256()
        blob = git_blob_sha(st.st_size)
        head = bytearray()
        total = 0
        with open(_long(dest), "xb") as out:
            while True:
                chunk = os.read(fd, CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                sha.update(chunk)
                blob.update(chunk)
                if len(head) < scan_bytes:
                    head += chunk[: scan_bytes - len(head)]
                out.write(chunk)
        if total != st.st_size:
            raise SnapshotError("changed-during-snapshot")
    finally:
        os.close(fd)
    try:
        st2 = os.lstat(_long(src))
        if st2.st_size != cand.size or st2.st_mtime_ns != cand.mtime_ns or _is_link(st2):
            raise SnapshotError("changed-during-snapshot")
    except OSError:
        raise SnapshotError("vanished-during-snapshot") from None
    os.chmod(_long(dest), stat.S_IREAD)
    entry = {"path": cand.rel, "size": total, "sha256": sha.hexdigest(), "blob": blob.hexdigest()}
    return entry, bytes(head), total > scan_bytes


def file_mode(rel: str, patterns: list[str]) -> str:
    return "100755" if any(match(p, rel, False) for p in patterns) else "100644"


def verify_tree(tree: str, manifest: list[dict]) -> list[str]:
    """Re-hash the staged tree; return a list of problems (empty if intact)."""
    problems = []
    expected = {m["path"]: m for m in manifest}
    found = set()
    for dirpath, dirnames, filenames in os.walk(tree, followlinks=False):
        for d in list(dirnames):
            if os.path.islink(os.path.join(dirpath, d)):
                problems.append(f"link in snapshot: {d}")
                dirnames.remove(d)
        for fn in filenames:
            ap = os.path.join(dirpath, fn)
            rel = os.path.relpath(ap, tree).replace("\\", "/")
            if os.path.islink(ap):
                problems.append(f"link in snapshot: {rel}")
                continue
            found.add(rel)
            m = expected.get(rel)
            if m is None:
                problems.append(f"unexpected file in snapshot: {rel}")
                continue
            h = hashlib.sha256()
            with open(_long(ap), "rb") as f:
                for chunk in iter(lambda: f.read(CHUNK), b""):
                    h.update(chunk)
            if h.hexdigest() != m["sha256"]:
                problems.append(f"content changed in snapshot: {rel}")
    for rel in expected.keys() - found:
        problems.append(f"missing from snapshot: {rel}")
    return problems


def source_like(rel: str) -> bool:
    return bool(SOURCE_LIKE.search(rel))


def tracked_in_local_git(git: str, root: str) -> set[str] | None:
    """Read-only list of files tracked by the project's own repository (if any),
    used only to flag tracked files that the policy excludes."""
    if not os.path.isdir(os.path.join(root, ".git")):
        return None
    try:
        r = run([git, *GIT_SAFE, "-c", f"safe.directory={root}", "-C", root,
                 "ls-files", "-z", "--cached"], what="git ls-files", timeout=120,
                env=git_env({"GIT_OPTIONAL_LOCKS": "0"}))
    except ProcError:
        return None
    return {p.decode("utf-8", "replace") for p in r.out.split(b"\0") if p}
