"""Cathodemon's command line.

    python -m cathodemon                 open the desktop app
    python -m cathodemon shield [...]    run DNS Shield without the window
    python -m cathodemon test [suite]    run the import audit and the test suites
    python -m cathodemon audit           check every import is the stdlib or our own

On Windows, `cdm.cmd` in the project folder runs the same commands from any
folder: `cdm`, `cdm shield`, `cdm test`, `cdm audit`. In PowerShell, run it
from the project folder as `.\\cdm`.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

# (name, script, what it checks). Every suite runs with -S, which hides all
# installed packages, so a pass also proves only the standard library is used.
SUITES = [
    ("audit", "audit_imports.py", "every import is the standard library or our own code"),
    ("crypto", "try_crypto.py", "the cipher and RSA, against the RFC test vectors"),
    ("dns", "try_dns.py", "DNS packets, the resolver and the DNS Shield server (uses the network)"),
    ("core", "try_core.py", "Recon, secure messages and the password tools (uses the network)"),
    ("properties", "try_properties.py", "property-based tests over random inputs (crypto, DNS, rules, passwords)"),
    ("gui", "try_gui.py", "opens the window and drives every screen"),
]

def _help() -> str:
    lines = [
        "usage: cdm [command]",
        "",
        "  cdm                  open the app",
        "  cdm shield [...]     run DNS Shield without the window (cdm shield --help lists the options)",
    ]
    if (SCRIPTS / "demo.py").exists():  # a local-only recorder, not in the repo
        lines.append("  cdm demo [screen]    play a self-driving demo for the video (cdm demo --help lists the screens)")
    lines += [
        "  cdm test             run the import audit and every test suite",
        "  cdm test <suite>     run some of them: " + ", ".join(name for name, _s, _d in SUITES),
        "  cdm audit            check that every import is the standard library or our own code",
        "  cdm help             show this help",
        "",
        "Without cdm, use python -m cathodemon in its place, for example python -m cathodemon shield.",
    ]
    return "\n".join(lines)


def open_app() -> int:
    # Imported here so `shield`, `test` and `audit` also work on machines
    # without a display or without Tkinter, such as a Raspberry Pi.
    import tkinter as tk

    from .app import App

    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


def run_shield(args) -> int:
    from .shield import main as shield_main

    return shield_main(args, prog="cdm shield")


def run_demo(args) -> int:
    return subprocess.call([sys.executable, "-S", str(SCRIPTS / "demo.py"), *args], cwd=ROOT)


def run_audit() -> int:
    return subprocess.call([sys.executable, "-S", str(SCRIPTS / "audit_imports.py")], cwd=ROOT)


def run_tests(names) -> int:
    known = [name for name, _script, _desc in SUITES]
    wanted = [n.lower() for n in names]
    unknown = [n for n in wanted if n not in known]
    if unknown:
        print(f"unknown test suite: {', '.join(unknown)}. Choose from: {', '.join(known)}")
        return 2
    chosen = [s for s in SUITES if not wanted or s[0] in wanted]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    failed = 0
    for name, script, desc in chosen:
        print(f"  {name:<11}", end="", flush=True)
        start = time.monotonic()
        proc = subprocess.run([sys.executable, "-S", str(SCRIPTS / script)], cwd=ROOT, env=env,
                              capture_output=True, text=True, encoding="utf-8", errors="replace")
        took = time.monotonic() - start
        lines = (proc.stdout + proc.stderr).splitlines()
        passes = sum(1 for line in lines if line.startswith("PASS"))
        fails = [line for line in lines if line.startswith("FAIL")]
        ok = proc.returncode == 0 and not fails
        if passes:
            detail = f"{passes} checks"
        else:
            detail = next((line.strip() for line in lines if line.startswith("Third-party imports")), "")
        print(f"{'PASS' if ok else 'FAIL'}  {detail:<24} {took:5.1f}s   {desc}", flush=True)
        if not ok:
            failed += 1
            for line in fails or lines[-8:]:
                print("           " + line)
    if failed:
        print(f"{failed} of {len(chosen)} failed")
        return 1
    print("all checks passed")
    return 0


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # some consoles can't show every character
    args = list(sys.argv[1:] if argv is None else argv)
    command = args[0].lower() if args else "app"
    rest = args[1:]
    if command == "app":
        return open_app()
    if command == "shield":
        return run_shield(rest)
    if command == "demo" and (SCRIPTS / "demo.py").exists():
        return run_demo(rest)
    if command == "test":
        return run_tests(rest)
    if command == "audit":
        return run_audit()
    if command in ("help", "-h", "--help", "/?"):
        print(_help())
        return 0
    print(f"unknown command: {args[0]}\n")
    print(_help())
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
