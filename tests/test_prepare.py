"""Prepare = read-only for sources and GitHub. Policy, completeness, secrets, privacy, links."""

import json
import os

import pytest

from conftest import (FAKE_AWS, FAKE_GH_TOKEN, FAKE_PRIVKEY, FAKE_SLACK_HOOK, tree_digest, write)
from publisher.service import PublishError


def manifest_paths(pub, plan_id):
    d = os.path.join(pub.root, "plans", plan_id)
    with open(os.path.join(d, "manifest.json")) as f:
        return {m["path"]: m for m in json.load(f)}


def test_prepare_is_read_only_and_never_writes_github(env):
    before = tree_digest(env.src)
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["status"] == "ready", r["blocking"]
    assert r["action"] == "create"
    assert tree_digest(env.src) == before                     # original untouched
    calls = env.fake()["calls"]
    assert not any("POST" in c for c in calls)                # no remote writes
    assert not os.path.exists(env.remote_gd())


def test_selective_exclusions_and_includes(env):
    pub = env.publisher()
    r = pub.prepare("demo")
    m = manifest_paths(pub, r["plan_id"])
    must_have = ["app/src/main/java/demo/MainActivity.kt",
                 "app/src/main/java/demo/state/RouteState.kt",      # nested 'state' package kept
                 "gradlew", "gradle/wrapper/gradle-wrapper.jar", "local.properties.example",
                 ".env.example", "README.md", ".gitignore", "app/src/main/res/drawable/icon.png"]
    for p in must_have:
        assert p in m, p
    must_not = ["local.properties", "settings.json", "app/build/outputs/app-debug.apk",
                ".gradle/cache.bin", ".venv/lib/x.py", "state/api-token.txt", "logs/run.log",
                "secret-notes/n.md", "notes.local", "tracks/morning.gpx", ".git/config", ".git/HEAD"]
    for p in must_not:
        assert p not in m, p
    assert m["gradlew"]["mode"] == "100755"
    assert m["README.md"]["mode"] == "100644"
    assert r["excluded_summary"]["project-gitignore"] == 2


def test_required_path_missing_blocks(env):
    env.project["required_paths"] = ["app/src/main", "app/src/test"]
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["status"] == "blocked"
    assert any(b["rule"].startswith("required-path-missing") and b["path"] == "app/src/test" for b in r["blocking"])


def test_excluded_source_is_reported(env):
    env.project["exclude"] = ["/app/src/main/java/demo/state/"]
    env.project["required_paths"] = []
    pub = env.publisher()
    r = pub.prepare("demo")
    assert "app/src/main/java/demo/state/RouteState.kt" not in manifest_paths(pub, r["plan_id"])
    write(env.src, "app/src/main/Config.kt.local", "x")   # source-like + gitignored
    r = pub.prepare("demo")
    assert r["excluded_source_like"]["count"] >= 1


@pytest.mark.parametrize("rel,content,rule", [
    ("app/src/main/java/demo/Api.kt", f'val token = "{FAKE_GH_TOKEN}"\n', "github-token"),
    ("docs/notes.weird", f"aws {FAKE_AWS}\n", "aws-access-key"),
    ("tools/blob.dat", b"\x00\x01binary" + FAKE_PRIVKEY.encode() + b"\x00", "private-key"),
    ("app/keystore.gradle", "storePassword=hunter2hunter2\n", "android-signing-password"),
], ids=["github-token", "aws-key-unknown-ext", "private-key-in-binary", "signing-password"])
def test_secrets_block_and_never_leak(env, rel, content, rule):
    write(env.src, rel, content)
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["status"] == "blocked"
    assert any(b["path"] == rel and b["rule"] == rule for b in r["blocking"]), r["blocking"]
    # zero leakage: the value is nowhere in plans/state/audit/review output
    secret = (content if isinstance(content, str) else content.decode("latin-1"))
    for needle in (FAKE_GH_TOKEN, FAKE_AWS, "hunter2hunter2", "MIIEowIBAAKCAQEA"):
        if needle in secret:
            assert needle.encode() not in env.all_data_bytes()
            assert needle not in json.dumps(r)
    assert not os.path.exists(os.path.join(pub.root, "plans", r["plan_id"], "tree"))   # copy discarded


def test_gitleaks_runs_and_project_config_cannot_disable_it(env):
    write(env.src, ".gitleaks.toml", '[allowlist]\npaths = [".*"]\n')
    write(env.src, ".gitleaksignore", "*\n")
    write(env.src, "app/src/main/res/raw/hooks.txt", f"url = {FAKE_SLACK_HOOK}  # gitleaks:allow\n")
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["gitleaks"] == "ran"
    assert any(b["rule"].startswith("gitleaks:") and b["path"] == "app/src/main/res/raw/hooks.txt"
               for b in r["blocking"]), r["blocking"]
    assert FAKE_SLACK_HOOK.encode() not in env.all_data_bytes()


def test_gitleaks_missing_blocks_when_required(env):
    pub = env.publisher(gitleaks=False)
    r = pub.prepare("demo")
    assert r["status"] == "blocked"
    assert any("gitleaks-not-installed" in b["rule"] for b in r["blocking"])


def test_location_traces_block(env):
    rows = "\n".join(f"35.{8900 + i:04d}12,14.{4100 + i:04d}55" for i in range(60))
    write(env.src, "docs/journey.csv", "lat,lon\n" + rows)
    write(env.src, "app/src/test/Fixture.kt", 'val p = "35.899912, 14.514455"\n')   # one point: fine
    pub = env.publisher()
    r = pub.prepare("demo")
    assert any(b["path"] == "docs/journey.csv" and b["rule"].startswith("location-data") for b in r["blocking"])
    assert not any(b["path"] == "app/src/test/Fixture.kt" for b in r["blocking"])


def test_reviewed_hash_pinned_exception(env):
    rows = "\n".join(f"35.{8900 + i:04d}12,14.{4100 + i:04d}55" for i in range(60))
    p = write(env.src, "app/src/test/resources/synthetic-route.csv", rows)
    import hashlib
    sha = hashlib.sha256(open(p, "rb").read()).hexdigest()
    env.project["reviewed"] = [{"path": "app/src/test/resources/synthetic-route.csv", "sha256": sha,
                                "rule": "*", "note": "synthetic test route, reviewed"}]
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["status"] == "ready", r["blocking"]
    assert r["acknowledged_count"] == 1
    write(env.src, "app/src/test/resources/synthetic-route.csv", rows + "\n35.912345,14.512345")
    r = pub.prepare("demo")                    # content changed -> exception no longer applies
    assert r["status"] == "blocked"


def test_symlink_inside_tree_blocks_but_not_in_excluded_dir(env, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("outside secret")
    os.symlink(str(outside), os.path.join(env.src, ".venv", "link.txt"))     # excluded area: ignored
    pub = env.publisher()
    assert pub.prepare("demo")["status"] == "ready"
    os.symlink(str(tmp_path), os.path.join(env.src, "app", "escape"))        # directory link
    r = pub.prepare("demo")
    assert r["status"] == "blocked"
    assert any(b["path"] == "app/escape" and "symlink" in b["rule"] for b in r["blocking"])
    assert b"outside secret" not in env.all_data_bytes()


def test_root_symlink_and_unknown_alias_and_bad_plan_ids(env, tmp_path):
    link = tmp_path / "rootlink"
    os.symlink(env.src, str(link))
    env.project["source"] = str(link)
    pub = env.publisher()
    with pytest.raises(Exception, match="symlink|junction|resolves"):
        pub.prepare("demo")
    for bad in ("../demo", "demo/../../x", "", "C:\\x"):
        with pytest.raises(PublishError):
            pub.prepare(bad)
    for bad in ("../../etc", "a/b", "x" * 80, "..", "demo-000000000000"):
        with pytest.raises(PublishError):
            pub.review(bad)


def test_windows_reserved_and_case_collision(env):
    write(env.src, "NUL", "junk from a shell redirect")
    write(env.src, "docs/Readme.TXT", "a")
    write(env.src, "docs/readme.txt", "b")
    pub = env.publisher()
    r = pub.prepare("demo")
    assert any(w["path"] == "NUL" and w["rule"] == "windows-reserved-name" for w in r["warnings"])
    assert any(b["rule"] == "case-insensitive-path-collision" for b in r["blocking"])


def test_oversized_file_blocks(env):
    write(env.src, "app/src/main/assets/big.bin", b"\x00" * (1024 * 1024 + 1))
    pub = env.publisher()
    r = pub.prepare("demo")
    assert any(b["rule"].startswith("oversized") for b in r["blocking"])


def test_prepare_is_idempotent(env):
    pub = env.publisher()
    a = pub.prepare("demo")
    b = pub.prepare("demo")
    assert a["plan_id"] == b["plan_id"] and a["snapshot_sha256"] == b["snapshot_sha256"]
    write(env.src, "README.md", "# changed\n")
    c = pub.prepare("demo")
    assert c["plan_id"] != a["plan_id"]


def test_hooks_and_filters_in_source_never_execute(env, tmp_path):
    marker = tmp_path / "PWNED"
    write(env.src, ".git/hooks/pre-commit", f"#!/bin/sh\ntouch {marker}\n", 0o755)
    write(env.src, ".git/config", f"[filter \"evil\"]\n\tclean = touch {marker}\n\tsmudge = touch {marker}\n"
                                  f"[core]\n\tfsmonitor = touch {marker}\n")
    write(env.src, ".gitattributes", "* filter=evil\n")
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["status"] == "ready", r["blocking"]
    from conftest import approve
    approve(pub, r["plan_id"])
    assert not marker.exists()


def test_workflow_scope_required(env):
    write(env.src, ".github/workflows/ci.yml", "on: push\n")
    env.set_fake(scopes="repo, read:org")
    pub = env.publisher()
    r = pub.prepare("demo")
    assert any("workflow-scope" in b["rule"] for b in r["blocking"])
    env.set_fake(scopes="repo, workflow")
    assert pub.prepare("demo")["status"] == "ready"


def test_false_positive_shapes_do_not_block(env):
    # header string used in code, and credential-rejection tests on reserved example hosts
    write(env.src, "app/src/test/KeyTest.kt",
          'val pem = text.replace("-----BEGIN ' + 'PRIVATE KEY-----", "")\n'
          'val bad = listOf("https://user:secretpw@example.test", "https://a:b1234@host.invalid")\n')
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["status"] == "ready", r["blocking"]


def test_suggest_reviewed_and_stale_tmp_cleanup(env):
    rows = "\n".join(f"35.{8900 + i:04d}12,14.{4100 + i:04d}55" for i in range(60))
    write(env.src, "tests/fixtures/coverage.json", rows)
    pub = env.publisher()
    r = pub.prepare("demo")
    sug = pub.suggest_reviewed(r["plan_id"], "location-data")
    assert sug and sug[0]["path"] == "tests/fixtures/coverage.json" and len(sug[0]["sha256"]) == 64
    os.makedirs(os.path.join(pub.root, "plans", ".tmp-deadbeef"))
    env.publisher()
    assert not os.path.exists(os.path.join(pub.root, "plans", ".tmp-deadbeef"))
