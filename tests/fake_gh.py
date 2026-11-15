#!/usr/bin/env python3
"""Minimal fake of the `gh api` subset used by GhBackend, backed by local bare
Git repositories. State lives in $GH_CONFIG_DIR/fake.json. Used only by tests."""

import json
import os
import subprocess
import sys

STATE_DIR = os.environ["GH_CONFIG_DIR"]
STATE = os.path.join(STATE_DIR, "fake.json")


def load():
    with open(STATE) as f:
        return json.load(f)


def save(s):
    with open(STATE, "w") as f:
        json.dump(s, f)


def fail(code, msg):
    sys.stderr.write(f"gh: {msg} (HTTP {code})\n")
    sys.exit(1)


def git(gd, *args):
    env = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "HOME": STATE_DIR}
    return subprocess.run(["git", f"--git-dir={gd}", *args], capture_output=True, env=env)


def main(argv):
    s = load()
    s.setdefault("calls", []).append(argv)
    save(s)
    if argv[:1] == ["auth"]:
        sys.exit(0)
    if argv[:1] != ["api"]:
        fail(400, "unsupported")
    args = argv[1:]
    if not s.get("auth", True):
        fail(401, "Bad credentials; run gh auth login")
    if s.get("network_down"):
        sys.stderr.write("error connecting to api.github.com\n")
        sys.exit(1)
    include = "-i" in args
    args = [a for a in args if a != "-i"]
    method = "GET"
    if "-X" in args:
        i = args.index("-X")
        method = args[i + 1]
        del args[i:i + 2]
    fields = {}
    path = None
    i = 0
    while i < len(args):
        if args[i] in ("-f", "-F"):
            k, v = args[i + 1].split("=", 1)
            fields[k] = v
            i += 2
        else:
            path = args[i]
            i += 1
    repos = s.setdefault("repos", {})
    owner = s.get("login", "Nundrian")

    if path == "user":
        body = json.dumps({"login": owner})
        if include:
            sc = s.get("scopes", "repo, workflow, read:org")
            print(f"HTTP/2.0 200 OK\nX-Oauth-Scopes: {sc}\n\n{body}")
        else:
            print(body)
        return
    if path == "user/repos" and method == "POST":
        name = fields["name"]
        key = f"{owner}/{name}".lower()
        if key in repos:
            fail(422, "name already exists on this account")
        gd = os.path.join(s["remotes"], owner, name + ".git")
        os.makedirs(os.path.dirname(gd), exist_ok=True)
        subprocess.run(["git", "init", "-q", "--bare", gd], check=True)
        s["next_id"] = s.get("next_id", 1000) + 1
        priv = fields.get("private") == "true" and not s.get("create_public")
        repos[key] = {"id": s["next_id"], "name": name, "private": priv, "gd": gd, "owner": owner}
        save(s)
        if s.get("create_then_fail"):
            s["create_then_fail"] = False
            save(s)
            fail(502, "Bad gateway")
        print(json.dumps({"id": s["next_id"], "private": priv, "visibility": "private" if priv else "public",
                          "owner": {"login": owner}, "html_url": f"https://github.com/{owner}/{name}"}))
        return
    parts = path.split("?")[0].split("/")
    if parts[0] == "repos" and len(parts) >= 3:
        key = f"{parts[1]}/{parts[2]}".lower()
        r = repos.get(key)
        if r is None:
            fail(404, "Not Found")
        rest = parts[3:]
        if not rest:
            print(json.dumps({"id": r["id"], "private": r["private"],
                              "visibility": "private" if r["private"] else "public", "archived": False,
                              "default_branch": "main", "owner": {"login": r["owner"]},
                              "html_url": f"https://github.com/{r['owner']}/{r['name']}"}))
            return
        if rest[:3] == ["git", "ref", "heads"]:
            br = "/".join(rest[3:])
            cp = git(r["gd"], "rev-parse", "--verify", "-q", f"refs/heads/{br}")
            if cp.returncode != 0:
                if git(r["gd"], "for-each-ref").stdout.strip() == b"":
                    fail(409, "Git Repository is empty.")
                fail(404, "Not Found")
            print(json.dumps({"object": {"sha": cp.stdout.decode().strip(), "type": "commit"}}))
            return
        if rest[:2] == ["git", "trees"]:
            sha = rest[2]
            cp = git(r["gd"], "ls-tree", "-r", "-t", "-z", sha)
            if cp.returncode != 0:
                fail(404, "Not Found")
            tree = []
            for rec in cp.stdout.split(b"\0"):
                if rec:
                    meta, p = rec.split(b"\t", 1)
                    mode, typ, osha = meta.decode().split()
                    tree.append({"path": p.decode(), "mode": mode, "type": typ, "sha": osha})
            print(json.dumps({"sha": sha, "tree": tree, "truncated": bool(s.get("truncate_tree"))}))
            return
        if rest[:2] == ["git", "commits"]:
            cp = git(r["gd"], "rev-parse", rest[2] + "^{tree}")
            if cp.returncode != 0:
                fail(404, "Not Found")
            print(json.dumps({"tree": {"sha": cp.stdout.decode().strip()}}))
            return
    fail(404, "Not Found")


if __name__ == "__main__":
    main(sys.argv[1:])
