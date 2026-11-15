import hashlib
import json
import os
import shutil
import stat
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from publisher.config import load_config            # noqa: E402
from publisher.github import GhBackend, GitHubError  # noqa: E402
from publisher.service import Publisher             # noqa: E402

GITLEAKS = shutil.which("gitleaks") or os.environ.get("GITLEAKS_BIN") or "/home/claude/tools-bin/gitleaks"

# Fake secrets are assembled at runtime so this test suite itself never contains
# a scanner-detectable literal.
FAKE_GH_TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FAKE_AWS = "AK" + "IA" + "QWERTYUIOPASDFGH"
FAKE_PRIVKEY = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEow" + "IBAAKCAQEA" * 8 + "\n-----END RSA PRIVATE KEY-----\n"
FAKE_SLACK_HOOK = "https://hooks.slack.com/services/" + "T0123ABCD/B0123ABCD/" + "aB3dE5fG7hI9jK1lM3nO5pQ7"


def write(root, rel, data, mode=None):
    p = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data.encode() if isinstance(data, str) else data)
    if mode:
        os.chmod(p, mode)
    return p


def tree_digest(root):
    """Hash of every byte, name and mode under root (follows nothing)."""
    h = hashlib.sha256()
    for dp, dns, fns in os.walk(root, followlinks=False):
        dns.sort()
        for fn in sorted(fns + [d for d in dns if os.path.islink(os.path.join(dp, d))]):
            p = os.path.join(dp, fn)
            st = os.lstat(p)
            h.update(os.path.relpath(p, root).encode() + str(st.st_mode).encode())
            if stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    h.update(f.read())
            elif stat.S_ISLNK(st.st_mode):
                h.update(os.readlink(p).encode())
    return h.hexdigest()


def make_android_project(root):
    write(root, "settings.gradle.kts", 'rootProject.name = "Demo"\ninclude(":app")\n')
    write(root, "build.gradle.kts", "plugins { }\n")
    write(root, "gradlew", "#!/bin/sh\necho gradle\n")
    write(root, "gradlew.bat", "@echo off\r\n")
    write(root, "gradle/wrapper/gradle-wrapper.properties", "distributionUrl=https\\://services.gradle.org/x.zip\n")
    write(root, "gradle/wrapper/gradle-wrapper.jar", b"PK\x03\x04\x00\x00fakejar")
    write(root, "app/build.gradle.kts", "android { }\n")
    write(root, "app/src/main/java/demo/MainActivity.kt", "package demo\nclass MainActivity\n")
    write(root, "app/src/main/java/demo/state/RouteState.kt", "package demo.state\nclass RouteState\n")
    write(root, "app/src/main/res/drawable/icon.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00binary")
    write(root, "README.md", "# Demo\n")
    write(root, ".gitignore", "/secret-notes/\n*.local\n")
    write(root, "local.properties", "sdk.dir=/x\n")
    write(root, "local.properties.example", "sdk.dir=C:/path/to/sdk\n")
    write(root, ".env.example", "API_KEY=changeme\n")
    write(root, "settings.json", '{"token": "x"}\n')
    write(root, "app/build/outputs/app-debug.apk", b"apk")
    write(root, ".gradle/cache.bin", b"cache")
    write(root, ".venv/lib/x.py", "x=1\n")
    write(root, "state/api-token.txt", "abc\n")
    write(root, "logs/run.log", "log\n")
    write(root, "secret-notes/n.md", "private\n")
    write(root, "notes.local", "private\n")
    write(root, "tracks/morning.gpx", "<gpx/>\n")
    write(root, ".git/config", "[core]\n")
    write(root, ".git/HEAD", "ref: refs/heads/main\n")


class FaultyBackend(GhBackend):
    """Real GhBackend (driven through the fake `gh`) with injectable push faults."""
    push_failures = 0

    def push(self, *a, **kw):
        if self.push_failures > 0:
            self.push_failures -= 1
            raise GitHubError("network", "simulated network failure during push")
        return super().push(*a, **kw)


class Env:
    def __init__(self, tmp):
        self.tmp = tmp
        self.src = os.path.join(tmp, "src", "Demo Project")
        os.makedirs(self.src)
        self.remotes = os.path.join(tmp, "remotes")
        self.ghdir = os.path.join(tmp, "ghconfig")
        os.makedirs(self.remotes)
        os.makedirs(self.ghdir)
        self.set_fake(remotes=self.remotes, login="Nundrian", auth=True)
        os.environ["GH_CONFIG_DIR"] = self.ghdir
        self.gh = os.path.join(tmp, "bin", "gh")
        os.makedirs(os.path.dirname(self.gh))
        with open(self.gh, "w") as f:
            f.write(f"#!/bin/sh\nexec {sys.executable} -I {os.path.join(HERE, 'fake_gh.py')} \"$@\"\n")
        os.chmod(self.gh, 0o755)
        self.data = os.path.join(tmp, "data")
        self.cfg_overrides = {}
        self.project = {"source": self.src, "repo": "Demo", "description": "demo",
                        "exclude": [], "include": [], "executable": ["gradlew"],
                        "required_paths": ["app/src/main", "gradlew"]}

    def fake(self):
        with open(os.path.join(self.ghdir, "fake.json")) as f:
            return json.load(f)

    def set_fake(self, **kw):
        p = os.path.join(self.ghdir, "fake.json")
        s = {}
        if os.path.exists(p):
            with open(p) as f:
                s = json.load(f)
        s.update(kw)
        with open(p, "w") as f:
            json.dump(s, f)

    def config_path(self, gitleaks=True, **scanner):
        cfg = {
            "schema": 1, "listen_port": 18766, "data_dir": self.data,
            "github": {"owner": "Nundrian", "gh_path": self.gh, "git_path": shutil.which("git"),
                       "git_base_url": "file://" + self.remotes},
            "scanner": {"gitleaks_path": GITLEAKS if gitleaks else "/nonexistent/gitleaks",
                        "require_gitleaks": True, "max_file_bytes": 1024 * 1024, **scanner},
            "projects": {"demo": self.project},
        }
        cfg.update(self.cfg_overrides)
        p = os.path.join(self.tmp, "publisher.json")
        with open(p, "w") as f:
            json.dump(cfg, f)
        return p

    def publisher(self, **kw):
        cfg = load_config(self.config_path(**kw))
        self.backend = FaultyBackend(cfg.gh_path, cfg.git_path, cfg.git_base_url)
        return Publisher(cfg, self.backend)

    def remote_gd(self, name="Demo"):
        return os.path.join(self.remotes, "Nundrian", name + ".git")

    def all_data_bytes(self, exclude_tree=True):
        out = b""
        for dp, dns, fns in os.walk(self.data):
            for fn in fns:
                p = os.path.join(dp, fn)
                with open(p, "rb") as f:
                    out += f.read()
        return out


@pytest.fixture
def env(tmp_path):
    e = Env(str(tmp_path))
    make_android_project(e.src)
    yield e
    os.environ.pop("GH_CONFIG_DIR", None)


def approve(pub, plan_id):
    """SIMULATED approval (what the Tool does after a real browser 'Confirm')."""
    ch = pub.challenge(plan_id)
    return pub.publish(plan_id, ch["challenge_id"], ch["nonce"],
                       hashlib.sha256(ch["message"].encode()).hexdigest())
