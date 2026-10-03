"""Regenerate requirements.txt (pip-compile) and keep it installable on every OS.

pip-compile resolves for the machine it runs on, so a lock made on Linux pins Linux-only packages without an
environment marker - e.g. uvloop (pulled in by uvicorn[standard]), which has no Windows build, and
`pip install -r requirements.txt` then fails on Windows. This script re-applies the markers.
Run: python scripts/lock.py   (or: make lock)
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "requirements.txt"
# package -> marker (same markers the dependent package itself declares)
PLATFORM_ONLY = {
    "uvloop": 'sys_platform != "win32" and sys_platform != "cygwin" and platform_python_implementation != "PyPy"',
}


def apply_markers(text: str) -> str:
    for pkg, marker in PLATFORM_ONLY.items():
        text = re.sub(rf"^({re.escape(pkg)}==[^\s;]+)(?:\s*;[^\n]*)?$", rf"\1 ; {marker}", text, flags=re.M)
    return text


def main() -> int:
    if "--markers-only" not in sys.argv:
        subprocess.run([sys.executable, "-m", "piptools", "compile", "-q", "--strip-extras", "--no-emit-index-url",
                        "--output-file", "requirements.txt", "requirements.in"], check=True, cwd=ROOT)
    LOCK.write_text(apply_markers(LOCK.read_text(encoding="utf-8")), encoding="utf-8")
    print(f"{LOCK.name}: platform markers applied for {', '.join(PLATFORM_ONLY)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
