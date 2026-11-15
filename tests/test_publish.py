"""Publish/verify against a mocked GitHub (fake `gh` + local bare repositories).
All approvals here are SIMULATED (the challenge/nonce protocol the Tool runs
after a real browser confirmation)."""

import hashlib
import json
import os
import subprocess
import time

import pytest

from conftest import approve, write
from publisher.service import PublishError


def git(gd, *a):
    return subprocess.run(["git", f"--git-dir={gd}", *a], capture_output=True, check=True).stdout


def remote_files(gd, ref="main"):
    out = {}
    for rec in git(gd, "ls-tree", "-r", "-z", ref).split(b"\0"):
        if rec:
            meta, p = rec.split(b"\t", 1)
            mode, _, sha = meta.decode().split()
            out[p.decode()] = (mode, git(gd, "cat-file", "blob", sha))
    return out


def test_end_to_end_create_publish_verify(env):
    pub = env.publisher()
    r = pub.prepare("demo")
    res = approve(pub, r["plan_id"])
    assert res["published"] and res["verification"]["ok"], res
    fake = env.fake()
    assert fake["repos"]["nundrian/demo"]["private"] is True
    files = remote_files(env.remote_gd())
    # independent byte-for-byte comparison with the ORIGINAL source files
    with open(os.path.join(pub.root, "plans", r["plan_id"], "manifest.json")) as f:
        manifest = json.load(f)
    assert set(files) == {m["path"] for m in manifest}
    for path, (mode, data) in files.items():
        with open(os.path.join(env.src, *path.split("/")), "rb") as f:
            assert f.read() == data, path
    assert files["gradlew"][0] == "100755"
    assert "settings.json" not in files and "local.properties" not in files
    log = git(env.remote_gd(), "log", "--format=%an <%ae>|%s", "main").decode()
    assert "Nundrian <Nundrian@users.noreply.github.com>" in log
    v = pub.verify("demo")
    assert v["verification"]["ok"]
    assert sum(1 for c in fake["calls"] if "user/repos" in c) == 1


def test_approval_must_match_plan_and_is_single_use(env):
    pub = env.publisher()
    pid = pub.prepare("demo")["plan_id"]
    ch = pub.challenge(pid)
    good_hash = hashlib.sha256(ch["message"].encode()).hexdigest()
    for bad in [(ch["challenge_id"], "wrong-nonce", good_hash),
                ("nope", ch["nonce"], good_hash)]:
        with pytest.raises(PublishError, match="approval"):
            pub.publish(pid, *bad)
    ch = pub.challenge(pid)
    with pytest.raises(PublishError, match="approval"):
        pub.publish(pid, ch["challenge_id"], ch["nonce"], "0" * 64)       # dialog text mismatch
    with pytest.raises(PublishError, match="approval"):                    # consumed even on failure
        pub.publish(pid, ch["challenge_id"], ch["nonce"], hashlib.sha256(ch["message"].encode()).hexdigest())
    ch = pub.challenge(pid)
    pub.challenges[ch["challenge_id"]]["expires"] = time.time() - 1
    with pytest.raises(PublishError, match="expired"):
        pub.publish(pid, ch["challenge_id"], ch["nonce"], hashlib.sha256(ch["message"].encode()).hexdigest())
    assert not os.path.exists(env.remote_gd())


def test_approval_cannot_be_reused_for_another_plan(env):
    pub = env.publisher()
    pid_a = pub.prepare("demo")["plan_id"]
    ch = pub.challenge(pid_a)
    write(env.src, "README.md", "# other tree\n")
    pid_b = pub.prepare("demo")["plan_id"]
    with pytest.raises(PublishError, match="approval"):
        pub.publish(pid_b, ch["challenge_id"], ch["nonce"], hashlib.sha256(ch["message"].encode()).hexdigest())
    assert not os.path.exists(env.remote_gd())


def test_plan_and_snapshot_tampering_detected(env):
    pub = env.publisher()
    pid = pub.prepare("demo")["plan_id"]
    d = os.path.join(pub.root, "plans", pid)
    staged = os.path.join(d, "tree", "README.md")
    os.chmod(staged, 0o644)
    with open(staged, "w") as f:
        f.write("# injected\n")
    with pytest.raises(PublishError, match="snapshot"):
        pub.challenge(pid)
    pid = pub.prepare("demo")["plan_id"]
    d = os.path.join(pub.root, "plans", pid)
    with open(os.path.join(d, "tree", "extra.txt"), "w") as f:
        f.write("smuggled")
    with pytest.raises(PublishError, match="snapshot"):
        pub.challenge(pid)
    os.remove(os.path.join(d, "tree", "extra.txt"))
    mf = os.path.join(d, "manifest.json")
    m = json.load(open(mf))
    m[0]["sha256"] = "0" * 64
    json.dump(m, open(mf, "w"))
    with pytest.raises(PublishError, match="hash"):
        pub.challenge(pid)
    assert not os.path.exists(env.remote_gd())


def test_tamper_between_challenge_and_publish(env):
    pub = env.publisher()
    pid = pub.prepare("demo")["plan_id"]
    ch = pub.challenge(pid)
    staged = os.path.join(pub.root, "plans", pid, "tree", "README.md")
    os.chmod(staged, 0o644)
    open(staged, "w").write("swap")
    with pytest.raises(PublishError, match="snapshot"):
        pub.publish(pid, ch["challenge_id"], ch["nonce"], hashlib.sha256(ch["message"].encode()).hexdigest())
    assert not os.path.exists(env.remote_gd())


def test_source_change_after_prepare_publishes_only_reviewed_bytes(env):
    pub = env.publisher()
    pid = pub.prepare("demo")["plan_id"]
    write(env.src, "README.md", "# edited after review\n")
    write(env.src, "NEW.md", "new after review\n")
    approve(pub, pid)
    files = remote_files(env.remote_gd())
    assert files["README.md"][1] == b"# Demo\n" and "NEW.md" not in files


def test_wrong_account(env):
    env.set_fake(login="SomeoneElse")
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["status"] == "blocked" and any(b["rule"] == "wrong-github-account" for b in r["blocking"])
    env.set_fake(login="Nundrian")
    pid = pub.prepare("demo")["plan_id"]
    ch = pub.challenge(pid)
    env.set_fake(login="SomeoneElse")
    with pytest.raises(PublishError, match="different account"):
        pub.publish(pid, ch["challenge_id"], ch["nonce"], hashlib.sha256(ch["message"].encode()).hexdigest())
    assert not os.path.exists(env.remote_gd())


def test_existing_repo_not_ours_is_never_overwritten(env):
    subprocess.run(["git", "init", "-q", "--bare", env.remote_gd()], check=True)
    env.set_fake(repos={"nundrian/demo": {"id": 77, "name": "Demo", "private": True,
                                          "gd": env.remote_gd(), "owner": "Nundrian"}})
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["status"] == "blocked" and any("name-collision" in b["rule"] for b in r["blocking"])
    with pytest.raises(PublishError, match="status is blocked"):
        pub.challenge(r["plan_id"])


def test_repo_created_by_someone_between_prepare_and_publish(env):
    pub = env.publisher()
    pid = pub.prepare("demo")["plan_id"]
    subprocess.run(["git", "init", "-q", "--bare", env.remote_gd()], check=True)
    env.set_fake(repos={"nundrian/demo": {"id": 78, "name": "Demo", "private": True,
                                          "gd": env.remote_gd(), "owner": "Nundrian"}})
    with pytest.raises(PublishError, match="now exists"):
        pub.challenge(pid)


def test_repeat_calls_are_idempotent(env):
    pub = env.publisher()
    pid = pub.prepare("demo")["plan_id"]
    approve(pub, pid)
    assert pub.challenge(pid)["already_published"] is True
    r = pub.prepare("demo")
    assert r["action"] == "update_ff" and any(b["rule"] == "no-changes-since-last-publication" for b in r["blocking"])
    assert sum(1 for c in env.fake()["calls"] if "user/repos" in c) == 1


def test_interrupted_push_is_resumable_without_duplicate(env):
    pub = env.publisher()
    pid = pub.prepare("demo")["plan_id"]
    env.backend.push_failures = 1
    with pytest.raises(PublishError) as ei:
        approve(pub, pid)
    assert ei.value.extra["resumable"] is True
    pubrec = json.load(open(os.path.join(pub.root, "plans", pid, "publication.json")))
    assert pubrec["state"] == "repo_created" and pubrec["failed"]
    assert env.fake()["repos"]["nundrian/demo"]["private"]
    res = approve(pub, pid)                                # new approval resumes
    assert res["verification"]["ok"]
    assert sum(1 for c in env.fake()["calls"] if "user/repos" in c) == 1


def test_create_response_lost_adopts_only_empty_private_repo(env):
    env.set_fake(create_then_fail=True)
    pub = env.publisher()
    pid = pub.prepare("demo")["plan_id"]
    res = approve(pub, pid)
    assert res["verification"]["ok"]
    assert "repo_create_response_lost_adopted_empty" in open(os.path.join(pub.root, "audit.log")).read()


def test_repo_not_private_after_create_halts_before_push(env):
    env.set_fake(create_public=True)
    pub = env.publisher()
    pid = pub.prepare("demo")["plan_id"]
    with pytest.raises(PublishError, match="not private"):
        approve(pub, pid)
    assert git(env.remote_gd(), "for-each-ref") == b""   # nothing pushed


def test_auth_failure_and_network_outage(env):
    env.set_fake(auth=False)
    pub = env.publisher()
    r = pub.prepare("demo")
    assert r["status"] == "review_only" and r["remote"]["state"] == "unavailable"
    with pytest.raises(PublishError, match="status is review_only"):
        pub.challenge(r["plan_id"])
    env.set_fake(auth=True)
    pid = pub.prepare("demo")["plan_id"]
    ch = pub.challenge(pid)
    env.set_fake(network_down=True)
    with pytest.raises(PublishError, match="unavailable"):
        pub.publish(pid, ch["challenge_id"], ch["nonce"], hashlib.sha256(ch["message"].encode()).hexdigest())
    assert not os.path.exists(env.remote_gd())


def test_verification_detects_remote_divergence(env):
    pub = env.publisher()
    approve(pub, pub.prepare("demo")["plan_id"])
    env.set_fake(truncate_tree=True)
    assert pub.verify("demo")["verification"]["ok"] is False
    env.set_fake(truncate_tree=False)
    # someone else pushes to main directly
    gd = env.remote_gd()
    blob = subprocess.run(["git", f"--git-dir={gd}", "hash-object", "-w", "--stdin"], input=b"x",
                          capture_output=True, check=True).stdout.decode().strip()
    head = git(gd, "rev-parse", "main").decode().strip()
    tree = subprocess.run(["git", f"--git-dir={gd}", "mktree"], input=f"100644 blob {blob}\tX\n".encode(),
                          capture_output=True, check=True).stdout.decode().strip()
    c = subprocess.run(["git", f"--git-dir={gd}", "-c", "user.name=a", "-c", "user.email=a@b",
                        "commit-tree", tree, "-p", head, "-m", "x"], capture_output=True, check=True
                       ).stdout.decode().strip()
    git(gd, "update-ref", "refs/heads/main", c)
    v = pub.verify("demo")["verification"]
    assert v["ok"] is False and v["branch_head_matches"] is False
    # the next update must not overwrite their work: goes to a separate branch
    write(env.src, "README.md", "# v2\n")
    r = pub.prepare("demo")
    assert r["action"] == "update_branch" and r["target_ref"].startswith("refs/heads/publisher/")
    res = approve(pub, r["plan_id"])
    assert res["verification"]["ok"]
    assert git(gd, "rev-parse", "main").decode().strip() == c          # their commit untouched


def test_update_fast_forward_with_diff(env):
    pub = env.publisher()
    approve(pub, pub.prepare("demo")["plan_id"])
    first = git(env.remote_gd(), "rev-parse", "main").decode().strip()
    write(env.src, "README.md", "# v2\n")
    write(env.src, "docs/new.md", "new\n")
    os.remove(os.path.join(env.src, "gradlew.bat"))
    r = pub.prepare("demo")
    assert r["action"] == "update_ff"
    assert r["diff"]["added"]["sample"] == ["docs/new.md"]
    assert r["diff"]["modified"]["sample"] == ["README.md"]
    assert r["diff"]["removed"]["sample"] == ["gradlew.bat"]
    res = approve(pub, r["plan_id"])
    assert res["verification"]["ok"]
    assert git(env.remote_gd(), "rev-parse", "main~1").decode().strip() == first


def test_busy_lock(env):
    pub = env.publisher()
    pub.lock.acquire()
    try:
        with pytest.raises(PublishError, match="another"):
            pub.prepare("demo")
    finally:
        pub.lock.release()
