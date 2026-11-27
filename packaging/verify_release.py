#!/usr/bin/env python3
"""Verify the built release archive actually works from a clean unpack.

This is the check that the earlier round was missing: run everything with
PYTHONPATH explicitly *unset* and HOME pointing at an empty directory, because a
leaked PYTHONPATH silently masks a broken bundle (it did once).

    python3 packaging/verify_release.py            # default zip
    python3 packaging/verify_release.py --with-tests
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        FAILS.append(msg)


def clean_env(home: Path) -> dict:
    """Environment with no PYTHONPATH and an empty HOME — nothing can leak in."""
    # Drop the token env vars by name pattern too, so a legacy name the SDK still
    # honours cannot leak a real token into the isolated check.
    env = {k: v for k, v in os.environ.items()
           if k not in ("PYTHONPATH", "FREEWHEEL_SDK", "FREEWHEEL_CONFIG_DIR",
                        "FREEWHEEL_MEDIA_TOKEN")
           and not k.startswith(("NEBI", "PYNEBI"))}
    env["HOME"] = str(home)
    return env


def run(args, cwd: Path, env: dict, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(cwd), env=env, capture_output=True,
                          text=True, timeout=timeout)


def verify(zip_path: Path, *, with_tests: bool) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="fw_relverify_"))
    home = tmp / "home"
    home.mkdir()
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(tmp / "x")
    root = tmp / "x" / "benibust-release"
    check(root.is_dir(), "archive unpacks to benibust-release/")

    env = clean_env(home)
    print(f"\n[{zip_path.name}] clean env: PYTHONPATH unset, HOME={home}\n")

    # --- manifest integrity -------------------------------------------------
    manifest = json.loads((root / "MANIFEST.json").read_text())
    bad = []
    for f in manifest["files"]:
        p = root / f["path"]
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != f["sha256"]:
            bad.append(f["path"])
    check(not bad, f"manifest: {len(manifest['files'])} files hash-checked ({len(bad)} bad)")
    check(not manifest.get("dirty"), f"manifest records a clean tree (dirty={manifest.get('dirty')})")
    # The bundle carries Apache-2.0-derived modules, so the attribution must ship with it.
    notice = root / "NOTICE"
    check(notice.is_file() and "Apache License" in notice.read_text(encoding="utf-8"),
          "NOTICE present and carries the Apache-2.0 attribution")

    # --- entry points, no PYTHONPATH ---------------------------------------
    r = run([sys.executable, "benibust.py", "--help"], root, env)
    check(r.returncode == 0, "benibust.py --help runs with no setup")

    r = run([sys.executable, "tools/beni_probe.py", "--help"], root, env)
    check(r.returncode == 0,
          f"tools/beni_probe.py --help runs with no PYTHONPATH"
          + ("" if r.returncode == 0 else f" — {r.stderr.strip().splitlines()[-1:]}"))

    # The probe must also import cleanly (its --help exits before the SDK import
    # in some revisions, so import it explicitly).
    r = run([sys.executable, "-c",
             "import runpy,sys; sys.argv=['beni_probe.py','--help'];"
             "import importlib.util as u;"
             "s=u.spec_from_file_location('bp','tools/beni_probe.py');"
             "m=u.module_from_spec(s); s.loader.exec_module(m);"
             "print('PROBE_IMPORT_OK')"], root, env)
    check("PROBE_IMPORT_OK" in r.stdout,
          "tools/beni_probe.py imports the SDK from the release layout"
          + ("" if "PROBE_IMPORT_OK" in r.stdout else f" — {r.stderr.strip()[-200:]}"))

    r = run([sys.executable, "-m", "freewheel.ota", "doctor"], root,
            dict(env, PYTHONPATH=str(root / "sdk")))
    check("missing" in r.stdout and "hbre.img" in r.stdout,
          "freewheel.ota doctor runs and reports missing inputs")

    # --- a real end-to-end build -------------------------------------------
    if (root / "sdk" / "freewheel" / "ota.py").is_file():
        r = run([sys.executable, str(REPO / "packaging" / "build_smoke.py"), str(root)], root, env)
        check("RELEASE_BUILD_OK" in r.stdout,
              "builds a verified package end to end"
              + ("" if "RELEASE_BUILD_OK" in r.stdout else f" — {(r.stdout + r.stderr).strip()[-400:]}"))

    # --- the offline suites, if shipped ------------------------------------
    if with_tests:
        suites = ("test_ota.py", "test_ble.py", "test_md_ts.py", "test_cmd_proto.py",
                  "test_transport.py", "test_request.py", "test_zenoh_pico.py",
                  "test_crosscheck.py")
        for name in suites:
            p = root / "sdk" / "tests" / name
            if not p.is_file():
                check(False, f"{name} present")
                continue
            r = run([sys.executable, f"sdk/tests/{name}"], root,
                    dict(env, PYTHONPATH=str(root / "sdk")))
            tail = (r.stdout + r.stderr).strip().splitlines()
            last = tail[-1] if tail else "(no output)"
            check(r.returncode == 0, f"{name} passes — {last}")
            if r.returncode != 0:
                for line in tail[-12:]:
                    print(f"         {line}")

    print()
    if FAILS:
        print(f"{len(FAILS)} FAILURE(S) in {zip_path.name}")
        return 1
    print(f"{zip_path.name}: ALL CHECKS PASSED")
    return 0


def package_version() -> str:
    """Read `__version__` from the SDK package, same source `build_release.py` uses."""
    for line in (REPO / "sdk" / "freewheel" / "__init__.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip("\"'")
    return "0.0.0"


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a built release archive")
    ap.add_argument("zip", nargs="?", default=None)
    ap.add_argument("--out", default=str(REPO / "dist"))
    ap.add_argument("--with-tests", action="store_true")
    args = ap.parse_args()

    suffix = "-tests" if args.with_tests else ""
    zip_path = Path(args.zip) if args.zip else (
        Path(args.out) / f"benibust-{package_version()}{suffix}.zip")
    if not zip_path.is_file():
        print(f"no such archive: {zip_path}", file=sys.stderr)
        return 2
    return verify(zip_path, with_tests=args.with_tests)


if __name__ == "__main__":
    raise SystemExit(main())
