# GitHub Publisher for Open WebUI 0.12.5

Lets an ordinary Open WebUI chat **prepare → review → publish (after your click) → verify**
administrator-allowlisted local projects into separate **private** GitHub repositories,
without pasting files and without the model ever seeing file contents or credentials.

```
Open WebUI chat (container)                       Windows host (your user account)
┌───────────────────────────────┐  HTTP + bearer  ┌───────────────────────────────────────┐
│ Native Tool "GitHub Publisher"│ ──────────────► │ publisher service 127.0.0.1:8766      │
│ 5 functions, owns the browser │  host.docker.   │ allowlisted roots → read-only walk    │
│ confirmation (__event_call__) │  internal:8766  │ immutable snapshot + SHA-256 manifest │
└───────────────────────────────┘                 │ built-in scanner + gitleaks           │
                                                  │ git plumbing + gh (token stays in gh) │
                                                  └───────────────────────────────────────┘
```

* Python standard library only (3.10+). External programs: Git for Windows, GitHub CLI (`gh`), gitleaks.
* Original project folders are only ever opened for reading. Nothing is written into them.
* Owner pinned to `Nundrian`; repositories fixed per alias in the admin config; `safe-route-regional-data`
  is hard-blocked as a target.

## Tool functions (what the model sees)

| Function | Effect |
|---|---|
| `publisher_status()` | read-only: aliases, destinations, last published commit, gh login state |
| `prepare_publish(project)` | read-only for source and GitHub: stage snapshot, scan, return compact review + `plan_id` |
| `review_publish(plan_id)` | read-only: detailed bounded review (full manifest stays on disk) |
| `publish_reviewed(plan_id)` | **write**: shows an Open WebUI confirmation dialog with repo, PRIVATE, action, file count and snapshot SHA-256; publishes only if *you* click Confirm |
| `verify_publish(project)` | read-only: independently compares GitHub (privacy, branch head, every path/blob/mode) with the snapshot |

## Install (Windows, once)

1. **Prerequisites**: Python 3.10+ (`py` launcher; you have 3.14), Git for Windows (you have 2.54), and
   GitHub CLI: `winget install --id GitHub.cli -e`, then
   `gh auth login --hostname github.com --git-protocol https --web --scopes workflow`
   (log in as **Nundrian**; `workflow` is needed because SafeRoute contains `.github/workflows`).
2. Copy this folder to `C:\GitHubPublisher\app` (already done if you received it there).
3. `powershell -ExecutionPolicy Bypass -File C:\GitHubPublisher\app\scripts\install.ps1`
   – installs gitleaks 8.30.0 into `%LOCALAPPDATA%\GitHubPublisher\bin` after verifying its official SHA-256,
   writes `%LOCALAPPDATA%\GitHubPublisher\publisher.json` (from `config\publisher.example.json`), creates the
   service token. No PATH or global Git changes.
4. Review `%LOCALAPPDATA%\GitHubPublisher\publisher.json` (project paths, exclusions; see *Dry-run findings*).
5. Start: `scripts\start-publisher.cmd` (keep the window open; Ctrl+C or `scripts\stop-publisher.cmd` stops it).
   Optional autostart: Task Scheduler → *At log on* → run `start-publisher.cmd` as your user (not SYSTEM:
   gh's token lives in your Windows credential store).
6. Check container → host reachability: `scripts\check-docker-reachability.cmd` must print **401**.

## Install in Open WebUI (admin)

1. Workspace → **Tools** → **+ / Import** → paste `openwebui\github_publisher_tool.py` → Save (id `github_publisher`).
2. Tool ⚙ **Valves**: `service_token` = output of `scripts\show-token.cmd`; keep
   `service_url = http://host.docker.internal:8766`. Optionally set `allowed_user_ids` to your user id.
3. Tool **access**: private to you (do not share with groups). The Tool also refuses non-admin users.
4. **Do not** add the service under *External Tool Servers / OpenAPI*: the model must never reach the
   service directly; only this Tool (which owns the dialog) may.
5. In a chat: enable the tool (➕ / wrench menu) and use a tool-capable model with *native* function calling
   (default). Upgrades of Open WebUI: re-run `tests/owui_compat_check.py` against the new version, then
   re-save the Tool; the Tool declares `required_open_webui_version: 0.12.5`.

## Typical chat

> "Prepare SafeRoute for GitHub." → compact review + `plan_id`
> "Publish that plan." → a dialog appears in **your** browser; Cancel/close/timeout = nothing happens.
> "Verify SafeRoute on GitHub."

Updates later: prepare again → shows added/modified/removed vs. the last published commit → fast-forward
`main` (no force). If someone else changed `main`, the publisher pushes to a new branch
`publisher/<id>` instead and leaves `main` untouched.

## When prepare is *blocked*

Blocking items list path + rule + line only (never values). Fix by excluding the path in `exclude`, removing
the secret at source, or – after inspecting the file yourself – adding a hash-pinned exception:
`py -3 -m publisher --config %LOCALAPPDATA%\GitHubPublisher\publisher.json suggest-reviewed <plan_id>` prints
candidate `reviewed` entries (path + SHA-256). Paste only the ones you have checked; any later change to
the file re-blocks it.

## Tests

Linux/WSL: `python3 -m pytest tests` (needs pytest, pydantic, git, gitleaks on PATH or `GITLEAKS_BIN`).
Open WebUI compatibility: `tests/owui_compat_check.py` and `tests/integration/` (see docs/HANDOVER.md).
