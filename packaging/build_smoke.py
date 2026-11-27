#!/usr/bin/env python3
"""Smoke-build a real OTA package from inside an unpacked release directory.

Invoked by `packaging/verify_release.py` with the release root as argv[1]. Builds a
synthetic stock base plus genuine `mke2fs` ext4 images, then runs the actual
`benibust.build_package` + `freewheel.ota.verify_package` path and asserts the
result — so a broken bundle fails here rather than on the verifier's bench.

Prints RELEASE_BUILD_OK on success.
"""
from __future__ import annotations

import hashlib
import io
import json
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sdk"))

import benibust as fr           # noqa: E402
from freewheel import ota             # noqa: E402
from freewheel.ext4 import Ext4Image  # noqa: E402

work = Path(tempfile.mkdtemp(prefix="fw_smoke_"))
PATCH_AT = 1024


def elf(size: int, patch: int | None = None) -> bytes:
    h = bytearray(64)
    h[0:4] = b"\x7fELF"
    h[4], h[5], h[6] = 2, 1, 1
    struct.pack_into("<H", h, 18, ota.EM_AARCH64)
    blob = bytearray(bytes(h) + b"\x00" * (size - 64))
    if patch is not None:
        blob[patch:patch + 4] = fr.OTA_PATCH_OLD
    return bytes(blob)


def make_ext4(path: Path, files: dict[str, bytes]) -> None:
    subprocess.run(["truncate", "-s", "24M", str(path)], check=True)
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", str(path)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    overlay = work / (path.stem + "_ov")
    for remote, blob in files.items():
        p = overlay / remote.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(blob)
    Ext4Image(path).apply_overlay_and_deletes(
        overlay_dir=overlay, mode_overrides={r: 0o755 for r in files})


system_img = work / "system.img"
hbre_img = work / "hbre.img"
make_ext4(system_img, {"/usr/sbin/sshd": elf(8192)})
make_ext4(hbre_img, {"/bin/cam-service": elf(2048), "/bin/ota_tool": elf(2048)})

parts = {
    "gpt.conf": b"# gpt\n",
    "ota_process": elf(4096, PATCH_AT),
    "vbmeta.img": b"\x00" * 256,
    "boot.img": b"\x00" * 512,
    "system.img": system_img.read_bytes(),
    "mondo.img": b"\x00" * 512,
}
data = {
    "version": "26.11.0.1",
    "update_partition": ["ota_process", "system", "mondo"],
    "partition_info": {
        k: {"imgname": k, "md5sum": {k: hashlib.md5(v).hexdigest()}, "md5_scope": {k: len(v)}}
        for k, v in parts.items()
    },
}
base = work / "all_in_one.zip"
with zipfile.ZipFile(base, "w", zipfile.ZIP_STORED) as zf:
    zf.writestr("data.json", json.dumps(data))
    for n, b in parts.items():
        zf.writestr(n, b)

fr.OTA_PATCH_OFFSET = PATCH_AT
pkg = work / "V26.11.19.50_lz110_freewheel.zip"
fr.build_package(base, hbre_img, pkg, "26.11.19.50", work / "build", payload="both",
                 ssh_pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIrelease-verify")

report = ota.verify_package(pkg, base_zip_path=base, allow_unsafe_x5_override=True)
assert report.package_version == "26.11.19.50"
assert report.verified_modules == 1

with zipfile.ZipFile(pkg) as zf:
    inner = [n for n in zf.namelist() if n.endswith(".mass.fw.plain.unsign")][0]
    with zipfile.ZipFile(io.BytesIO(zf.read(inner))) as iz:
        patched = work / "patched_hbre.img"
        patched.write_bytes(iz.read("hbre.img"))

img = Ext4Image(patched)
img.fsck()
assert img.path_exists("/bin/ota_tool"), "hbre lost ota_tool — unusable for future flashes"
assert img.path_exists("/bin/md_sshd") and img.path_exists("/bin/cam-service.real")
hook = img.read_file("/bin/cam-service").decode()
assert "freewheel" in hook and "md_sshd" in hook and "cam-service.real" in hook
assert (img.stat_path("/bin/freewheel_authorized_keys").mode & 0o777) == 0o600

print(f"package {pkg.name} ({pkg.stat().st_size:,} B), partitions {report.verified_x5_partitions}")
print("RELEASE_BUILD_OK")
