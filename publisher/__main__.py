"""CLI: python -m publisher --config publisher.json <command>

Commands (none of them publish; publishing requires the Open WebUI approval dialog):
  serve                 run the loopback service
  status                print status JSON
  prepare <alias>       local staging + audit (read-only for sources)
  review <plan_id>      print the detailed review
  verify <alias>        independently compare GitHub with the last published snapshot
  show-token            print the service token (for pasting into the Tool valve)
  suggest-reviewed <plan_id> [rule-prefix]
                        print hash-pinned 'reviewed' entries for blocking findings, to paste
                        into the config ONLY after you have inspected each file yourself
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import ConfigError, load_config


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="publisher")
    ap.add_argument("--config", required=True)
    ap.add_argument("command", choices=["serve", "status", "prepare", "review", "verify", "show-token",
                                        "suggest-reviewed"])
    ap.add_argument("arg", nargs="?")
    ap.add_argument("arg2", nargs="?", default="")
    a = ap.parse_args(argv)
    try:
        cfg = load_config(a.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    if a.command == "serve":
        from .server import serve
        serve(cfg)
        return 0
    if a.command == "show-token":
        from .server import ensure_token
        print(ensure_token(cfg.token_file))
        return 0
    from .service import Publisher, PublishError
    pub = Publisher(cfg)
    try:
        if a.command == "status":
            out = pub.status()
        elif a.command == "prepare":
            out = pub.prepare(a.arg or "")
        elif a.command == "suggest-reviewed":
            out = pub.suggest_reviewed(a.arg or "", a.arg2)
        elif a.command == "review":
            out = pub.review(a.arg or "", detail=True)
        else:
            out = pub.verify(a.arg or "")
    except PublishError as exc:
        out = {"error": exc.code, "message": str(exc), **exc.extra}
    print(json.dumps(out, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
