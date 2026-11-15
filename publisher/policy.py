"""Selective exclusion policy.

Order of evaluation for each path (relative, '/'-separated):
  1. hard rules (Windows reserved names, invalid names)          -> excluded/blocked
  2. default + project exclusions                                -> excluded
  3. project `include` overrides re-include a default exclusion  (scanners still apply)
  4. the project's own .gitignore files (via `git check-ignore`) -> excluded
"""

from __future__ import annotations

import re
from functools import lru_cache

# Directory names excluded at any depth (generated output, caches, VCS, IDE state).
DIRS_ANY = [
    ".git", ".hg", ".svn", ".gradle", ".idea", ".kotlin", ".venv", "venv", "__pycache__",
    "node_modules", ".next", ".vs", ".vscode", "build", "dist", "out", "target",
    "Intermediate", "Saved", "DerivedDataCache", "Binaries", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".cxx", ".externalNativeBuild", ".android-sdk", ".cache",
]
# Excluded only directly under the project root (legitimate source packages may reuse names).
DIRS_ROOT = [
    "state", "work", "logs", "cache", "caches", "tmp", "temp", "telemetry", "traces",
    "journeys", "sessions", "uploads", "recordings", "captures", "user-data", "user_data",
    "backups", "secrets", "signing", ".agents", ".codex", ".firecrawl", ".claude",
]
# File name globs excluded anywhere.
FILES_ANY = [
    ".env", ".env.*", "settings.json", "local.properties", "google-services.json",
    "GoogleService-Info.plist", "api-token.txt", "operator-key.txt", "credentials.json",
    "secrets.properties", "keystore.properties", "*.secret", "*.token", "*.key", "*.pem",
    "*.p12", "*.pfx", "*.jks", "*.keystore", "*.der", "id_rsa*", "id_ed25519*", "id_ecdsa*",
    ".netrc", "_netrc", ".npmrc", ".pypirc", "*.ovpn", "*.kdbx",
    "*.apk", "*.aab", "*.apks", "*.gpx", "*.fit", "*.kml", "*.kmz", "*.pbf", "*.osm",
    "*.mbtiles", "*.gpkg", "*.rd5", "*.ghz", "*.hprof", "*.db", "*.db-wal", "*.db-shm",
    "*.sqlite", "*.sqlite3", "*.log", "*.jsonl", "*.pid", "*.tmp", "*.bak", "*.orig",
    "*.swp", "*.zip", "*.7z", "*.rar", "*.tar", "*.gz", "*.tgz", "*.xz", "*.bz2",
    "*.pyc", "*.class", "*.dex", "*.so", "*.dll", "*.exe", "*.pdb", "*.obj",
    ".DS_Store", "Thumbs.db", "desktop.ini",
]
# Re-included by default (examples/templates are expected to be published, then scanned).
INCLUDE_DEFAULT = ["*.example", "*.example.*", "*.sample", "*.template", ".env.example"]

WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$", re.I)
BAD_NAME = re.compile(r'[<>:"\\|?*\x00-\x1f]|[. ]$')

SOURCE_LIKE = re.compile(
    r"\.(py|kt|kts|java|gradle|xml|toml|cfg|ini|json|ya?ml|md|txt|ps1|cmd|bat|sh|c|cc|cpp|h|hpp|cs|"
    r"js|ts|tsx|jsx|html|css|sql|properties|pro|cmake|rs|go|swift)$", re.I)


@lru_cache(maxsize=4096)
def _glob_rx(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?"); i += 3; continue
        if pattern.startswith("**", i):
            out.append(".*"); i += 2; continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i)
            if j == -1:
                out.append(re.escape(c))
            else:
                out.append("[" + pattern[i + 1:j].replace("\\", "\\\\") + "]"); i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.I)


def match(pattern: str, rel: str, is_dir: bool) -> bool:
    """Gitignore-like: trailing '/' = directory only; a '/' elsewhere anchors to root;
    otherwise the pattern matches the base name at any depth."""
    dir_only = pattern.endswith("/")
    p = pattern.strip("/")
    if not p:
        return False
    if dir_only and not is_dir:
        return False
    anchored = pattern.startswith("/") or "/" in p
    target = rel if anchored else rel.rsplit("/", 1)[-1]
    return bool(_glob_rx(p).match(target))


class Policy:
    def __init__(self, project_exclude: list[str], project_include: list[str]):
        self.exclude = list(project_exclude)
        self.include = INCLUDE_DEFAULT + list(project_include)

    def name_problem(self, name: str) -> str | None:
        if WINDOWS_RESERVED.match(name):
            return "windows-reserved-name"
        if BAD_NAME.search(name):
            return "invalid-windows-name"
        return None

    def _included(self, rel: str, is_dir: bool) -> bool:
        return any(match(p, rel, is_dir) for p in self.include)

    def dir_reason(self, rel: str) -> str | None:
        name = rel.rsplit("/", 1)[-1]
        depth0 = "/" not in rel
        reason = None
        if any(name.lower() == d.lower() for d in DIRS_ANY):
            reason = "default-dir"
        elif depth0 and any(name.lower() == d.lower() for d in DIRS_ROOT):
            reason = "default-root-dir"
        elif any(match(p, rel, True) for p in self.exclude):
            reason = "project-exclude"
        if reason and name.lower() != ".git" and self._included(rel, True):
            return None
        return reason

    def file_reason(self, rel: str) -> str | None:
        name = rel.rsplit("/", 1)[-1]
        reason = None
        if any(match(p, name, False) for p in FILES_ANY):
            reason = "default-file"
        elif any(match(p, rel, False) for p in self.exclude):
            reason = "project-exclude"
        if reason and self._included(rel, False):
            return None
        return reason
