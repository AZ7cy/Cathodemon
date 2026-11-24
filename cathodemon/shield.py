"""Run DNS Shield without the window, for an always-on machine.

    python -m cathodemon.shield                 # listen on every interface, port 53
    python -m cathodemon.shield --port 5353     # a test port
    python -m cathodemon.shield --verbose       # print every blocked lookup

Then set your router's DNS server to this machine's address. Ctrl+C stops it.
"""
from __future__ import annotations

import argparse
import sys
import time

from .core.blocklist import load_rules
from .core.sinkhole import Shield, lan_ip


def main(argv=None, prog: str = "python -m cathodemon.shield") -> int:
    parser = argparse.ArgumentParser(prog=prog,
                                     description="Cathodemon DNS Shield - network-wide ad and phishing blocker")
    parser.add_argument("--host", default="0.0.0.0", help="address to listen on (default: all)")
    parser.add_argument("--port", type=int, default=53, help="port to listen on (default: 53)")
    parser.add_argument("--no-smart", action="store_true", help="turn off look-alike phishing blocking")
    parser.add_argument("--allow-public", action="store_true",
                        help="also answer clients outside the local network (not recommended)")
    parser.add_argument("--verbose", action="store_true", help="print every blocked lookup")
    args = parser.parse_args(argv)

    rules = load_rules(smart=not args.no_smart)
    shield = Shield(rules, host=args.host, port=args.port, local_only=not args.allow_public)
    try:
        shield.start()
    except OSError as exc:
        print(f"Could not listen on {args.host}:{args.port}: {exc}", file=sys.stderr)
        print("Another DNS server may be using that port. On Linux, port 53 needs root "
              "(sudo) and systemd-resolved may already hold it. Try --port 5353 to test.",
              file=sys.stderr)
        return 1

    print(f"Cathodemon DNS Shield listening on {args.host}:{shield.port} (UDP and TCP)")
    print(f"  blocklist: {len(rules.builtin)} built-in + {len(rules.user_block)} yours, "
          f"allow list: {len(rules.allow)}, smart blocking: {'on' if rules.smart else 'off'}")
    print(f"  point your router's DNS at {lan_ip()}   (Ctrl+C to stop)")

    seen = 0
    last_summary = time.time()
    try:
        while True:
            time.sleep(1)
            st = shield.stats()
            if args.verbose:
                new = st["queries"] - seen
                for entry in reversed(st["recent"][:max(0, new)]):
                    if entry["action"] == "blocked":
                        print(f"  blocked {entry['name']} for {entry['client']}  ({entry['reason']})")
            seen = st["queries"]
            if time.time() - last_summary >= 60:
                last_summary = time.time()
                print(f"  {st['queries']} lookups, {st['blocked']} blocked "
                      f"({st['blocked_pct']:.1f}%), {st['local']} local")
    except KeyboardInterrupt:
        pass
    finally:
        shield.stop()
        print("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
