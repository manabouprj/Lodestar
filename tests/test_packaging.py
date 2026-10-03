"""The pinned lock must install on every OS LODESTAR supports (Linux containers, Windows and macOS hosts)."""
import re

from conftest import ROOT


def test_platform_only_pins_carry_markers():
    import importlib.util
    spec = importlib.util.spec_from_file_location("lock", ROOT / "scripts" / "lock.py")
    lock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lock)
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    for pkg in lock.PLATFORM_ONLY:
        line = re.search(rf"^{pkg}==.*$", text, re.M)
        assert line and 'sys_platform != "win32"' in line.group(0), f"{pkg} pinned without a Windows marker"
    assert lock.apply_markers("uvloop==1.0\n") == f"uvloop==1.0 ; {lock.PLATFORM_ONLY['uvloop']}\n"
    assert lock.apply_markers(lock.apply_markers("uvloop==1.0\n")) == lock.apply_markers("uvloop==1.0\n")   # idempotent


def test_lock_covers_direct_dependencies():
    lock = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    for line in (ROOT / "requirements.in").read_text(encoding="utf-8").splitlines():
        name = re.split(r"[<>=\[ #;]", line.strip(), maxsplit=1)[0].lower()
        if name:
            assert re.search(rf"^{re.escape(name)}==", lock, re.M), f"{name} missing from requirements.txt"
