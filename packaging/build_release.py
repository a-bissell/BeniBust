#!/usr/bin/env python3
"""Build the self-contained BeniBust release zip for secondary verification.

The repo carries research notes, simulators, and captured evidence that a second
verifier doesn't need. This assembles the **jailbreak only** — the SDK modules the
build and flash path actually imports, the CLI entry point, the read-only probe,
and the operating docs — into one zip that runs from a clean checkout with no
`pip install` of anything in this project.

    python3 packaging/build_release.py            # -> dist/benibust-<ver>.zip
    python3 packaging/build_release.py --with-tests   # include the offline suites

The zip root is `benibust-release/`, so an unzip gives one directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VERSION_FILE = REPO / "sdk" / "freewheel" / "__init__.py"

# The SDK modules shipped here. `__init__.py` imports the whole package eagerly, so
# this is the full module set (all stdlib) rather than only what the build path
# reaches — keeping the release byte-identical to the tree the tests run against
# instead of a trimmed variant. `sitl/` is the minimal loopback robot the offline
# tests drive; it needs no web console and no hardware.
JAILBREAK_MODULES = (
    "__init__.py",
    "ble.py",
    "capture.py",
    "client.py",
    "cmd_proto.py",
    "cmd_schemas.json",
    "conformance.py",
    "control.py",
    "diagnostics.py",
    "ext4.py",
    "fwextract.py",
    "md_ts.py",
    "ota.py",
    "probe.py",
    "tracking.py",
    "transport.py",
    "zenoh.py",
    "zenoh_pico.py",
    "zenoh_session.py",
)

# Read-only diagnostics the verifier will want; imports only client + ota.
TOOLS = ("beni_probe.py",)

DOCS = ("docs/BENIBUST.md",)

TEST_FILES = ("test_ota.py", "test_ble.py", "test_md_ts.py", "test_cmd_proto.py",
              "test_transport.py", "test_zenoh_pico.py", "test_request.py",
              "test_crosscheck.py")

# The simulated robot the offline suites drive, shipped with `--with-tests` so the
# end-to-end cases (OTA upload, MD-TS handshake, request/response) run from the zip.
SITL_PACKAGE = "sitl"


def package_version() -> str:
    for line in VERSION_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip("\"'")
    return "0.0.0"


def _copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)


def stage(root: Path, *, with_tests: bool) -> Path:
    out = root / "benibust-release"
    (out / "sdk" / "freewheel").mkdir(parents=True)

    for name in JAILBREAK_MODULES:
        _copy(REPO / "sdk" / "freewheel" / name, out / "sdk" / "freewheel" / name)

    for name in TOOLS:
        _copy(REPO / "tools" / name, out / "tools" / name)

    for name in DOCS:
        _copy(REPO / name, out / "docs" / Path(name).name)

    _copy(REPO / "benibust.py", out / "benibust.py")
    # Required attribution: the release bundles the modules NOTICE covers.
    _copy(REPO / "NOTICE", out / "NOTICE")
    for extra in ("PACKAGING-README.md", "requirements.txt"):
        _copy(REPO / "packaging" / extra, out / extra)

    if with_tests:
        shutil.copytree(REPO / "sdk" / "freewheel" / SITL_PACKAGE,
                        out / "sdk" / "freewheel" / SITL_PACKAGE,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (out / "sdk" / "tests").mkdir(parents=True, exist_ok=True)
        for name in TEST_FILES:
            _copy(REPO / "sdk" / "tests" / name, out / "sdk" / "tests" / name)
        if (REPO / "sdk" / "tests" / "crosscheck").is_dir():
            shutil.copytree(REPO / "sdk" / "tests" / "crosscheck",
                            out / "sdk" / "tests" / "crosscheck",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    return out


def provenance() -> dict:
    def _git(*args: str) -> str:
        try:
            return subprocess.check_output(["git", *args], cwd=REPO, text=True,
                                           stderr=subprocess.DEVNULL).strip()
        except (OSError, subprocess.CalledProcessError):
            return ""

    return {
        "version": package_version(),
        "commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(_git("status", "--porcelain")),
        "built_utc": subprocess.check_output(
            [sys.executable, "-c",
             "import datetime;print(datetime.datetime.now(datetime.timezone.utc)"
             ".strftime('%Y-%m-%dT%H:%M:%SZ'))"], text=True).strip(),
    }


def write_manifest(out: Path, prov: dict, *, with_tests: bool) -> None:
    entries = []
    for path in sorted(out.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(out).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({"path": rel, "bytes": path.stat().st_size, "sha256": digest})
    manifest = {
        "package": "benibust-release",
        **prov,
        "includes_tests": with_tests,
        "file_count": len(entries),
        "files": entries,
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def build(dest: Path, *, with_tests: bool) -> Path:
    prov = provenance()
    suffix = "-tests" if with_tests else ""
    dest = dest / f"benibust-{prov['version']}{suffix}.zip"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fw_release_") as tmp:
        out = stage(Path(tmp), with_tests=with_tests)
        write_manifest(out, prov, with_tests=with_tests)
        with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for path in sorted(out.rglob("*")):
                if path.is_file():
                    zf.write(path, path.relative_to(out.parent).as_posix())
    return dest


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the BeniBust release zip")
    ap.add_argument("--out", default=str(REPO / "dist"), help="output directory (default: dist/)")
    ap.add_argument("--with-tests", action="store_true", help="include the offline test suites")
    args = ap.parse_args()

    dest = build(Path(args.out), with_tests=args.with_tests)
    size = dest.stat().st_size
    print(f"built {dest}  ({size / 1024:.0f} KiB)")
    with zipfile.ZipFile(dest) as zf:
        names = zf.namelist()
    print(f"  {len(names)} entries")
    for name in names:
        print(f"    {name}")
    print()
    print(f"  sha256 {hashlib.sha256(dest.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
