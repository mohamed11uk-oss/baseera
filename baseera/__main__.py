"""CLI: python -m baseera analyze <url|text> | serve | export-openapi | feeds refresh|count"""
from __future__ import annotations

import argparse
import json
import sys


def main(argv=None):
    p = argparse.ArgumentParser(prog="baseera")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a URL or a pasted message")
    a.add_argument("input")
    a.add_argument("--json", action="store_true")
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    sub.add_parser("export-openapi")
    f = sub.add_parser("feeds", help="PhishTank / OpenPhish blocklist feeds (local SQLite)")
    f.add_argument("action", choices=["refresh", "count"])
    f.add_argument("--source", choices=["phishtank", "openphish", "all"], default="all")
    f.add_argument("--force", action="store_true", help="ignore each source's refresh cadence")
    args = p.parse_args(argv)
    if args.cmd == "analyze":
        from .analyze import Analyzer
        an = Analyzer()
        v = an.analyze_text(args.input) if " " in args.input.strip() else an.analyze_url(args.input)
        if args.json:
            print(v.model_dump_json(indent=2))
        else:
            print(f"Risk {v.risk}/100 ({v.level})\n\n{v.explanation_ar}\n\n{v.explanation_en}")
    elif args.cmd == "serve":
        import uvicorn
        uvicorn.run("baseera.api:create_app", factory=True, host=args.host, port=args.port)
    elif args.cmd == "feeds":
        return feeds_cli(args)
    elif args.cmd == "export-openapi":
        import os
        os.environ.setdefault("BASEERA_DB", ":memory:")
        from .api import create_app
        json.dump(create_app().openapi(), sys.stdout, ensure_ascii=False, indent=1)


def feeds_cli(args, client=None) -> int:
    from .config import get_settings
    from .sources.feeds import SOURCES, FeedStore

    st = get_settings()
    store = FeedStore(st.feeds_db)
    names = list(SOURCES) if args.source == "all" else [args.source]
    if args.action == "refresh":
        if st.offline:
            print("BASEERA_MODE=offline: not downloading feeds (set BASEERA_MODE=live).")
            return 2
        if "phishtank" in names and not st.phishtank_app_key:
            print("note: PHISHTANK_APP_KEY not set; using the keyless PhishTank URL (stricter rate limits).")
        for n in names:
            r = store.refresh(n, app_key=st.phishtank_app_key, client=client, force=args.force,
                              timeout_s=st.feeds_download_timeout_s)
            print(f"{n:10s} {r['status']:24s} {r['count']} entries")
    else:
        meta = store.meta()
        for n in names:
            m = meta.get(n, {})
            print(f"{n:10s} {m.get('count', 0):>7} entries  last refresh: {m.get('last_success') or 'never'}  "
                  f"status: {m.get('status') or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
