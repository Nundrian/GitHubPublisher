"""Subprocess execution: argument arrays only, fixed executables, timeouts,
hardened Git environment and secret redaction of anything captured."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass

_REDACT = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)(authorization:\s*)(\S+\s+)?\S+"),
    re.compile(r"(?i)(password|token|secret)=\S+"),
    re.compile(r"https://[^/\s:@]+:[^@\s]+@"),
]


def redact(text: str) -> str:
    for rx in _REDACT:
        text = rx.sub("[REDACTED]", text)
    return text


class ProcError(RuntimeError):
    def __init__(self, what: str, code: int | None, detail: str):
        super().__init__(f"{what} failed (exit {code}): {redact(detail)[:400]}")
        self.code = code
        self.detail = redact(detail)[:2000]


@dataclass
class Result:
    code: int
    out: bytes
    err: str


_EMPTY_GLOBAL: str | None = None


def _empty_gitconfig() -> str:
    """An empty file used as the global Git config so the user's global
    hooks/filters/aliases/credential helpers never apply implicitly."""
    global _EMPTY_GLOBAL
    if _EMPTY_GLOBAL is None or not os.path.exists(_EMPTY_GLOBAL):
        fd, p = tempfile.mkstemp(prefix="ghpub-empty-", suffix=".gitconfig")
        os.close(fd)
        _EMPTY_GLOBAL = p
    return _EMPTY_GLOBAL


def git_env(extra: dict | None = None) -> dict:
    keep = ("PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "HOME", "USERPROFILE",
            "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "COMSPEC", "PATHEXT", "LANG",
            "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "SSL_CERT_FILE", "HTTPS_PROXY",
            "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
            "USERNAME", "USERDOMAIN", "SystemDrive", "ProgramFiles", "ProgramW6432", "windir",
            "HOMEDRIVE", "HOMEPATH", "NUMBER_OF_PROCESSORS", "OS", "PROCESSOR_ARCHITECTURE")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": _empty_gitconfig(),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GCM_INTERACTIVE": "never",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "NO_COLOR": "1",
    })
    if extra:
        env.update(extra)
    return env


NULL_HOOKS = "NUL" if sys.platform == "win32" else "/dev/null"

# -c overrides that beat any repository-level configuration.
GIT_SAFE = [
    "-c", f"core.hooksPath={NULL_HOOKS}",
    "-c", "core.fsmonitor=false",
    "-c", "core.autocrlf=false",
    "-c", "core.symlinks=false",
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=user",
    "-c", "submodule.recurse=false",
    "-c", "commit.gpgsign=false",
    "-c", "credential.helper=",
]


def run(argv: list[str], *, what: str, timeout: int = 120, input: bytes | None = None,
        env: dict | None = None, cwd: str | None = None, check: bool = True) -> Result:
    if not argv or not os.path.isabs(argv[0]):
        raise ProcError(what, None, "executable must be an absolute, pre-resolved path")
    try:
        cp = subprocess.run(argv, input=input, capture_output=True, timeout=timeout,
                            env=env if env is not None else git_env(), cwd=cwd,
                            shell=False, stdin=None if input is not None else subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise ProcError(what, None, f"timed out after {timeout}s") from None
    except OSError as exc:
        raise ProcError(what, None, exc.__class__.__name__) from None
    err = cp.stderr.decode("utf-8", "replace")
    if check and cp.returncode != 0:
        raise ProcError(what, cp.returncode, err)
    return Result(cp.returncode, cp.stdout, redact(err))
