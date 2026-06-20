"""Smoke check: parse every new Python file and report syntax errors."""
import ast
import pathlib
import sys

roots = [
    pathlib.Path("backend/memory"),
    pathlib.Path("backend/memory_integration.py"),
    pathlib.Path("scripts"),
]
files = []
for r in roots:
    p = pathlib.Path(r)
    if p.is_file():
        files.append(p)
    elif p.is_dir():
        files.extend(p.rglob("*.py"))

bad = 0
for f in files:
    try:
        ast.parse(f.read_text(encoding="utf-8"))
    except SyntaxError as e:
        bad += 1
        print(f"FAIL {f}: line {e.lineno}: {e.msg}")
print(f"\nParsed {len(files)} files, {bad} syntax errors.")
sys.exit(1 if bad else 0)
