"""Audit: prove every import in this project is either the Python standard
library or the project's own `cathodemon` package.

Parses each .py file (it does not run them) and classifies every import.
Also flags dynamic imports (__import__ / importlib.import_module) and
exec/eval, which could hide an import from a plain text search.
Exit code 0 = clean, 1 = something outside the standard library was found.
"""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STDLIB = set(sys.stdlib_module_names) | {"__future__"}
# First-party code: the package, plus any module that lives in scripts/, since a
# test helper may import a sibling there (try_properties.py imports pbt.py).
LOCAL = {"cathodemon"} | {p.stem for p in (ROOT / "scripts").glob("*.py")}
SUSPECT_CALLS = {"__import__", "import_module", "exec", "eval"}

files = sorted(p for p in ROOT.rglob("*.py") if "__pycache__" not in p.parts)
stdlib, local, foreign, dynamic = set(), set(), [], []

for path in files:
    rel = path.relative_to(ROOT)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(rel))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            tops = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import such as "from . import rsa"
                local.add("cathodemon")
                continue
            tops = [(node.module or "").split(".")[0]]
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute) else "")
            if name in SUSPECT_CALLS:
                dynamic.append(f"{rel}:{node.lineno}  {name}()")
            continue
        else:
            continue
        for top in tops:
            if top in LOCAL:
                local.add(top)
            elif top in STDLIB:
                stdlib.add(top)
            else:
                foreign.append(f"{rel}:{node.lineno}  imports '{top}'")

print(f"Scanned {len(files)} Python files")
print(f"Standard-library modules used ({len(stdlib)}): {', '.join(sorted(stdlib))}")
print(f"Project-local imports: {', '.join(sorted(local)) or '(none)'}")
print(f"Third-party imports: {len(foreign)}")
for item in foreign:
    print("   ", item)
print(f"Dynamic imports / exec / eval: {len(dynamic)}")
for item in dynamic:
    print("   ", item)
sys.exit(1 if foreign or dynamic else 0)
