# GitHub Publisher — technical handover (2026-11-15)

Status keys: **IMPLEMENTED** · **MEASURED** (ran against real data/software) · **MOCKED** (simulated
dependency) · **UNTESTED** · **BLOCKED** (could not be done here; reason given).

## 1. Decision record (evidence)

| Option | Finding | Decision |
|---|---|---|
| GitHub official MCP server (MIT; `create_repository`, `push_files`, `create_or_update_file`, `get_file_contents`; `--toolsets`, `--read-only`) | `push_files` takes `files[{path, content}]` as **strings supplied by the caller**, so every file would have to go through the local LLM's context. It has no local-filesystem, staging, audit or approval layer. Its transports are remote HTTP or local stdio/Docker. Stdio is not native to Open WebUI and would need an extra bridge. | **Not used.** It doesn't remove complexity here and would break "the model must not stream source". |
| Open WebUI native MCP / OpenAPI tool servers | External servers have no interactive confirmation, and the model can call every endpoint they expose. | Not used for the write path. The service must **not** be registered as a tool server. |
| Native Open WebUI Tool (`class Tools`, Valves, `__event_call__`) | Verified in the 0.12.5 source (`socket/main.py`, `Chat.svelte`). A confirmation returns `True` on Confirm and `False` on Cancel. On disconnect or timeout it returns `{'error': …}`. With no timeout set it waits indefinitely. `__*__` params are removed from the model schema, and model kwargs are filtered to the schema. | **Used.** Strict `answer is True`, own 180 s timeout, `None` caller ⇒ refuse. |
| Mechanisium/rws_tool_open-webui (GPL-3.0) | Path check uses `abspath` + `commonpath`. It does not resolve or refuse symlinks and doesn't handle junctions. | Pattern noted. **No code reused**, for licence reasons and because the check is weaker. |
| Community "end-to-end publisher" | Searched. Found single-file push tools (blog markdown via API), an Obsidian publisher that overwrites/deletes the remote folder, and a browser-cookie uploader. None reads local trees, stages, audits, asks for approval and verifies. | Built a small one. |
| gitleaks (MIT) | `gitleaks dir` scans a directory. Config precedence includes `<target>/.gitleaks.toml`, and `.gitleaksignore` and `gitleaks:allow` are honoured by default. | **Used** with an explicit config, an empty ignore path and `--ignore-gitleaks-allow`, so a project can't weaken it. Tested. |
| PowerShell prototype | Robocopy staging + regexes + `gh repo create --push`. It had no per-plan approval, no integrity hashes, weak recovery, and the `NUL` file would break it. | Its exclusion lists were kept and extended. The workflow was replaced. |

## 2. Architecture (IMPLEMENTED)

* `publisher/` is a host service, standard library only. It binds only `127.0.0.1:8766` (config refuses
  anything else) and requires a bearer token (constant-time compare). It refuses requests carrying
  `Origin`/`Sec-Fetch-*` (browser/DNS-rebinding), caps bodies at 4 KiB, and returns errors without traces or values.
* **Prepare** walks the canonical root with `lstat` and never follows links.
  * Symlinks, junctions and reparse points ⇒ blocking. A link inside an excluded directory is ignored.
  * UNC roots and roots that are links are refused. Windows-reserved names (`NUL`…) are excluded and warned. Case collisions are blocked.
  * Exclusions are default + root-only + project globs. Include overrides re-include default exclusions (still scanned). The project's **own `.gitignore`** is applied through `git check-ignore` with a *private empty git-dir*, so the project's `.git` config and hooks are never used.
  * Each file is copied with `O_NOFOLLOW` (POSIX), size/mtime re-checked after the read. SHA-256 and the Git blob SHA are computed from the bytes actually read. Staged files are made read-only.
  * Scanning covers built-in rules over every file (any extension, binary too) plus gitleaks over the staged tree. Findings record path, rule and line only.
  * Completeness checks: `required_paths`, policy-excluded source-like files, and files tracked by the local repo but excluded.
  * A blocked plan's staged copy is deleted.
* **Plan** = SHA-256 over destination, action, base commit, commit message and every (path, mode, blob, sha256, size). `plan_id = <alias>-<hash12>`. Prepare is idempotent.
* **Approval**: the Tool requests a challenge. The service re-verifies the staged tree, the GitHub account, scopes and remote state, then issues a 5-minute single-use nonce bound to the plan hash and to the SHA-256 of the exact dialog text. The Tool shows that text through `__event_call__` and returns the nonce only after `True`. The service consumes the challenge even if publishing fails.
* **Publish** re-checks everything under a lock. It builds the commit with Git plumbing (`hash-object --no-filters`, `update-index --index-info`, `write-tree`, `commit-tree`), so no checkout, hooks, filters, LFS or line-ending conversion is involved. It re-compares the built tree with the manifest.
  * New repo: create a private repo with `auto_init=false`. If the repo is not private, it halts before pushing.
  * Then it pushes with no force. Credentials come from `gh auth git-credential` for that one command, with an empty global Git config (`GIT_CONFIG_GLOBAL`), `GIT_CONFIG_NOSYSTEM` and `core.hooksPath=NUL`.
* **Verify** is independent: repository privacy, branch head = commit, and every remote path/mode/blob = manifest. Nothing extra or missing is allowed, and a truncated API tree counts as a failure.
* **Recovery**: `publication.json` and `state/projects.json` record each step.
  * If the push fails after creation, the next approval for the *same plan* resumes, with no duplicate repo.
  * If the create response is lost, the repo is adopted only if it is private and empty.
  * A name collision with a repo this tool didn't create is blocked, and nothing is overwritten.
  * If remote `main` moved, the next update goes to the new branch `publisher/<hash12>`.

## 3. Test results (MEASURED; full log in `docs/test-results.txt`)

| Suite | Result | Real vs simulated |
|---|---|---|
| `pytest tests` (Py 3.13 and Py 3.12) | **58 passed** both | Real git 2.43, real gitleaks 8.30.0, real HTTP. GitHub is **MOCKED** with a fake `gh` + local bare repos, driven through the production `GhBackend`. Browser answers are **MOCKED** callables. |
| Safety matrix covered | path escape, symlink dir/file, root link, bad aliases/plan ids, reserved names, case collisions, oversize, exclusions/includes, project `.gitignore`, required paths, excluded-source report, 4 secret types incl. a key inside a binary, gitleaks vs. hostile `.gitleaks.toml`/`.gitleaksignore`/`gitleaks:allow`, gitleaks missing, coordinate traces, hash-pinned exceptions (re-block on change), hostile hooks/filters/fsmonitor never run, workflow scope, plan tamper, snapshot tamper (before challenge and between challenge and publish), source edits after review (only reviewed bytes published), wrong account, existing repo collision, creation race, repeat calls, interrupted push resume, lost create response, repo turned public, auth failure, network outage, verification of truncation and divergence, FF update with diff, divergent `main` → branch, busy lock, HTTP auth/Origin/body limits, Tool cancel/disconnect/timeout/"yes"/1/None ⇒ no, no `__event_call__`, non-admin, user allowlist, unreachable service, zero secret leakage to plans/state/audit/review | |
| `tests/owui_compat_check.py` | **OK** | Real `open-webui==0.12.5` loader and spec generator: 5 functions, `publish_reviewed(plan_id)` only |
| `tests/integration/run_owui_integration.py` | **PASS** | **Real Open WebUI 0.12.5 server**: tool install API, valves, native function calling, socket.io `__event_call__`. Cancel ⇒ nothing. Smuggled `approved/__event_call__/confirm` args ⇒ dialog still shown, nothing. Confirm ⇒ published + verified private. LLM, browser and GitHub **MOCKED**. |
| Real dry-run Prepare on your PC | **MEASURED** (Linux VM reading your folders through the desktop bridge, Python 3.10, git, **without gh**, built-in scanner) + gitleaks run here on byte-identical copies (sha256-checked) | Source unchanged (UEHL metadata digest identical before/after). |

## 4. Dry-run findings (MEASURED) — decisions you need to make

**UEHL** (`uehl-bbfd4297505a`): 448 files, 3.3 MiB; 0 built-in blocks.
* Excluded: `.venv/ backups/ state/ work/ .pytest_cache/ __pycache__/`, `settings.json` (kept: `settings.example.json`), 78 `*.log`, 11 `*.jsonl`, 4 `*.zip`.
* Warnings: your Windows user path appears in 9 evidence files and in `tests/test_service.py`. One evidence file contains third-party e-mail addresses from research output.
* **gitleaks: 10 `generic-api-key` hits** in `evidence/{runtime,continuation}/{baseline,final-audit}.json`. They are SHA-256 file hashes (one is the hash of `state/api-token.txt`, which is not the token itself). These will block the real publish until you exclude those files or add reviewed entries.

**SafeRoute** (`saferoute-ba4f5e46ca3c`): 972 files, 68.4 MiB.
* Your project `.gitignore` excluded 325 files. Policy excluded `.android-sdk/ .gradle/ build/ data/ artifacts/ tools/graphhopper/ signing/ captures/ logs/ tmp/ work/ .agents/ .codex/ .firecrawl/`. `NUL` was excluded (Windows reserved name; the prototype's robocopy would have failed on it).
* **15 blocked for coordinate data**: 3 unit tests, 3 coverage masks under `tests/regional-*`, 9 route-output files under `docs/evidence/dependency-047` and `docs/reviews`. They look like synthetic or benchmark routes, not personal journeys, but only you can confirm that.
* **gitleaks: 17 `generic-api-key` hits** (key IDs such as `KEY_A_ID`, hash tables, `test-keys.json`).
* **42 files tracked in your local git are excluded by policy**:
  * offline-pack `.rd5` / `.mbtiles` / font `.pbf` under `app/src/main/assets`, `app/src/androidTest/assets` and `tests/mixed-routing-*`;
  * test keys `tests/offline-maps-01{5,6,7}/**/*-test-private.pem` and their public halves;
  * `app/src/debug/assets/offline-maps-017/staging-ca.pem`.

  Tests and the app read some of these, for example `CompositeOfflinePackProviderTest` reads `key-b-test-private.pem`. Without them, a GitHub-side build or test run will fail. To publish them, add precise `include` globs *and* reviewed entries. Test private keys are still private keys: GitHub secret scanning may flag them.
* Other notes: `docs/` is a nested Git repo (published as plain files, no history). `.github/workflows/ci.yml` needs the gh `workflow` scope.
* Hash-pinned candidates are in `dryrun-results/*-review-candidates.json`. They are **not active**: notes say "NOT YET REVIEWED".

Three false-positive shapes found on your real code were fixed and given regression tests: a PEM header string used in code, `user:pass@example.test` in credential-rejection tests, and stale plan reuse.

## 5. Support matrix

| Capability | Status |
|---|---|
| Create private repo / initial push / FF update / divergent → branch / resume / verify | IMPLEMENTED, MOCKED-tested; **UNTESTED against real github.com** (no approval given, by design) |
| Open WebUI 0.12.5 Tool loading, valves, native calling, confirmation dialog round-trip | MEASURED on a real 0.12.5 server (browser simulated) |
| Real browser click in *your* Open WebUI | UNTESTED (needs you) |
| Windows-specific paths (junction/reparse detection via `st_file_attributes`, `\\?\` long paths, `NUL` hooksPath, gh credential helper via Git-for-Windows sh, install/start scripts) | IMPLEMENTED, **UNTESTED on Windows**. The device bridge here is a Linux VM, and Windows command execution was not available. |
| Docker → host reachability for port 8766 | UNTESTED. Same mechanism UEHL verified for 8765. Use `scripts/check-docker-reachability.cmd` (expects 401). |
| gh installed / logged in as Nundrian / scopes | **BLOCKED here**: not visible from the VM. `install.ps1` and `publisher_status` report it. |
| PR creation, deletions, visibility changes, force push, history import | Not implemented (v1 by design) |

## 6. Security limitations (honest)

* The Tool holds the service token, and the service trusts the Tool's report that the user clicked Confirm. Anyone who can edit the Tool's code or read its valves (Open WebUI admins) could bypass the dialog. Keep the Tool private to your admin account. The model alone cannot: it gets no endpoint, token or nonce.
* On Windows, Python has no `O_NOFOLLOW`. Link checks are done before and after each read, which leaves a small TOCTOU window. The integrity of the published bytes is still guaranteed by the staged hashes.
* The scanners are heuristic. Coordinate detection is by density. A private repo is not a safety net. Read the review.
* Staged snapshots in `%LOCALAPPDATA%\GitHubPublisher\plans` are copies of your source. They are protected only by your user profile's NTFS permissions.
* The challenge store is in memory, so a service restart invalidates pending approvals (fail-closed).

## 7. Install / configure checklist

1. [ ] `winget install --id GitHub.cli -e` → `gh auth login --hostname github.com --git-protocol https --web --scopes workflow` as **Nundrian**
2. [ ] `powershell -ExecutionPolicy Bypass -File C:\GitHubPublisher\app\scripts\install.ps1`
3. [ ] Edit `%LOCALAPPDATA%\GitHubPublisher\publisher.json`: decide on the 42 tracked-but-excluded SafeRoute files; review and add `reviewed` entries or exclusions for the gitleaks and coordinate findings
4. [ ] `scripts\start-publisher.cmd`; `scripts\check-docker-reachability.cmd` → `401`
5. [ ] Open WebUI → Workspace → Tools → import `openwebui\github_publisher_tool.py`; set `service_token` (from `show-token.cmd`); keep the Tool private
6. [ ] Chat: "publisher status" → GitHub login Nundrian, workflow scope true, gitleaks present
7. [ ] Chat: "prepare uehl" → review → "publish" → click **Confirm** only if the dialog says `Nundrian/Unreal-Headless-Connector — PRIVATE`
8. [ ] Chat: "verify uehl" → `ok: true`; repeat for SafeRoute separately

Rollback: stop the service, delete the Tool in Open WebUI, delete `%LOCALAPPDATA%\GitHubPublisher`. Nothing
else on the system was changed. Created GitHub repositories are never deleted by this tool.
