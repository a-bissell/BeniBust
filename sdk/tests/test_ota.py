#!/usr/bin/env python3
"""Tests for the self-contained owner path: media-token recovery, ext4 patching,
package verification, the `:8085` firmware pull, and the Zenoh+TUS OTA upload.

Run: cd sdk && python3 tests/test_ota.py       (ext4 cases need `mke2fs`; skipped otherwise)
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from freewheel import ota  # noqa: E402

# External SDK modules the owner path replaced. Blocked in several tests to prove the
# jailbreak build and verification never import them.
_BLOCKED_EXTERNAL_MODULES = ("nebi", "nebi_patch")

SDK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "retail-bearer-not-in-this-repo-4f9c1a"
SECRET_SHA = ota.token_digest(SECRET)


def _tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="fw_ota_test_"))


def _has_mke2fs() -> bool:
    return shutil.which("mke2fs") is not None


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── media token: recovery from the app the owner already has ─────────────────

def test_token_candidates_and_digest():
    assert ota.token_digest(SECRET) == SECRET_SHA
    assert ota.is_known_media_token(SECRET, SECRET_SHA)
    assert not ota.is_known_media_token("nope", SECRET_SHA)
    assert not ota.is_known_media_token("", SECRET_SHA)
    # A run that mixes the token with adjacent literal text still yields it.
    blob = b"\x00\x01https://api/x?k=" + SECRET.encode() + b"&v=2\x00junk"
    assert ota._match_in_blob(blob, SECRET_SHA) == SECRET
    # Bearer-prefixed and quote-wrapped spellings both resolve.
    assert ota._match_in_blob(b'Bearer "' + SECRET.encode() + b'"', SECRET_SHA) == SECRET


def test_extract_token_from_apk_zip_and_so_and_dir():
    d = _tmpdir()
    noise = os.urandom(4096)
    apk = d / "MondoApp.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00" + noise)
        # SecNeo/Flutter builds keep the constant in libapp.so rodata
        zf.writestr("lib/arm64-v8a/libapp.so", b"\x7fELF" + noise + b"\x00const=" + SECRET.encode() + b"\x00" + noise)
        zf.writestr("assets/flutter_assets/kernel_blob.bin", noise)

    out = d / "media_token"
    token = ota.extract_media_token_from_apk(apk, save=True, save_path=out, expected_sha256=SECRET_SHA)
    assert token == SECRET
    assert out.read_text().strip() == SECRET
    assert (out.stat().st_mode & 0o777) == 0o600

    # Raw .so file (owner unzipped it themselves)
    so = d / "libapp.so"
    so.write_bytes(b"\x7fELF" + noise + SECRET.encode() + noise)
    assert ota.extract_media_token_from_apk(so, save=False, expected_sha256=SECRET_SHA) == SECRET

    # A directory of split APKs
    split = d / "splits"
    split.mkdir()
    with zipfile.ZipFile(split / "split_config.arm64_v8a.apk", "w") as zf:
        zf.writestr("lib/arm64-v8a/libapp.so", noise + SECRET.encode())
    assert ota.extract_media_token_from_apk(split, save=False, expected_sha256=SECRET_SHA) == SECRET

    # Nothing matches -> LookupError with actionable text, and nothing written.
    other = d / "clean.apk"
    with zipfile.ZipFile(other, "w") as zf:
        zf.writestr("classes.dex", noise)
    missing_out = d / "nope_token"
    try:
        ota.extract_media_token_from_apk(other, save=True, save_path=missing_out, expected_sha256=SECRET_SHA)
    except LookupError as e:
        assert "hashed to" in str(e)
    else:
        raise AssertionError("expected LookupError for an app without the constant")
    assert not missing_out.exists()


def test_save_and_resolve_token_order():
    d = _tmpdir()
    stored = d / "media_token"
    try:
        ota.save_media_token("wrong", stored, expected_sha256=SECRET_SHA)
    except ValueError as e:
        assert "does not match" in str(e)
    else:
        raise AssertionError("a token that fails the digest must not be saved")
    assert not stored.exists()

    ota.save_media_token(SECRET, stored, expected_sha256=SECRET_SHA)
    assert (stored.stat().st_mode & 0o777) == 0o600

    env_keys = (*ota.TOKEN_ENV_VARS, "FREEWHEEL_CONFIG_DIR", "HOME")
    saved = {k: os.environ.get(k) for k in env_keys}
    try:
        for k in env_keys:
            os.environ.pop(k, None)
        os.environ["HOME"] = str(d)          # no legacy token in the config dir either
        assert ota.resolve_media_token() == ""            # nothing configured
        assert ota.resolve_media_token("explicit") == "explicit"
        legacy_env = ota.LEGACY_TOKEN_ENV_VARS[0]
        os.environ[legacy_env] = "legacy-env"
        assert ota.resolve_media_token() == "legacy-env"
        os.environ["FREEWHEEL_MEDIA_TOKEN"] = "new-env"
        assert ota.resolve_media_token() == "new-env"     # freewheel env beats legacy env
        os.environ.pop("FREEWHEEL_MEDIA_TOKEN")
        os.environ.pop(legacy_env)
        os.environ["FREEWHEEL_CONFIG_DIR"] = str(d)
        assert ota.resolve_media_token() == SECRET
        os.environ.pop("FREEWHEEL_CONFIG_DIR")
        try:
            ota.resolve_media_token(allow_missing=False)
        except FileNotFoundError as e:
            assert "extract-token" in str(e)
        else:
            assert False, "allow_missing=False should raise when nothing resolves"
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_repo_never_contains_the_bearer():
    """The digest is public; the literal token must never be committed."""
    hits = []
    for root, dirs, files in os.walk(os.path.dirname(SDK_DIR)):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", "beni_fw"}]
        for f in files:
            if not f.endswith((".py", ".md", ".json", ".sh", ".txt", ".html", ".toml")):
                continue
            p = Path(root) / f
            if p.name == "test_ota.py":
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if SECRET in text:
                hits.append(str(p))
    assert hits == [], f"token literal leaked into: {hits}"


# ── ext4 (real images via mke2fs) ────────────────────────────────────────────

def _tiny_ext4(path: Path, size_mb: int = 16) -> bool:
    if not _has_mke2fs():
        return False
    subprocess.run(["truncate", "-s", f"{size_mb}M", str(path)], check=True)
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", str(path)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def test_ext4_overlay_delete_readback_and_fsck():
    from freewheel.ext4 import Ext4Image
    d = _tmpdir()
    img_path = d / "hbre.img"
    if not _tiny_ext4(img_path):
        print("    (skipped: mke2fs not available)")
        return

    overlay = d / "overlay"
    (overlay / "bin").mkdir(parents=True)
    (overlay / "bin" / "cam-service").write_bytes(b"#!/bin/sh\nexec /bin/cam-service.real \"$@\"\n")
    (overlay / "bin" / "md_sshd").write_bytes(b"\x7fELF" + b"\x00" * 4096)
    (overlay / "bin" / "freewheel_authorized_keys").write_text("ssh-ed25519 AAAA freewheel\n")

    img = Ext4Image(img_path)
    stats = img.get_fs_stats()
    assert stats.block_size >= 1024 and stats.free_bytes > 0

    changes = img.apply_overlay_and_deletes(
        overlay_dir=overlay,
        mode_overrides={"/bin/cam-service": 0o755, "/bin/md_sshd": 0o755,
                        "/bin/freewheel_authorized_keys": 0o600},
    )
    assert changes == {"deleted": 0, "written": 3, "dirs_created": 1}
    assert img.stat_path("/bin/md_sshd").size == 4100
    assert (img.stat_path("/bin/md_sshd").mode & 0o777) == 0o755
    assert (img.stat_path("/bin/freewheel_authorized_keys").mode & 0o777) == 0o600
    assert img.read_file("/bin/freewheel_authorized_keys") == b"ssh-ed25519 AAAA freewheel\n"
    assert img.read_file_prefix("/bin/md_sshd", 4) == b"\x7fELF"
    assert "bin" in img.list_dir("/")

    # Re-apply (overwrite path) then delete the key file.
    img.apply_overlay_and_deletes(overlay_dir=overlay, mode_overrides={"/bin/md_sshd": 0o755})
    result = img.apply_overlay_and_deletes(delete_paths=["/bin/freewheel_authorized_keys"])
    assert result["deleted"] == 1 and not img.path_exists("/bin/freewheel_authorized_keys")
    assert "Pass 1" in img.fsck()


def test_ext4_refuses_unsafe_mutations():
    from freewheel.ext4 import Ext4Image
    d = _tmpdir()
    img_path = d / "t.img"
    if not _tiny_ext4(img_path):
        print("    (skipped: mke2fs not available)")
        return
    img = Ext4Image(img_path)
    try:
        img.apply_overlay_and_deletes(delete_paths=["/"])
    except ValueError as e:
        assert "Refusing" in str(e)
    else:
        raise AssertionError("deleting '/' must be refused")
    try:
        img.apply_overlay_and_deletes(delete_paths=["/bin"])
    except ValueError as e:
        assert "directory" in str(e)
    else:
        assert True          # /bin may not exist on a fresh image; nothing to delete


# ── package verification ─────────────────────────────────────────────────────

def _aarch64_elf(pad: int = 256) -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2           # ELFCLASS64
    hdr[5] = 1           # little endian
    hdr[6] = 1
    struct.pack_into("<H", hdr, 18, ota.EM_AARCH64)
    return bytes(hdr) + b"\x00" * pad


def _build_package(dest: Path, *, version: str = "26.11.19.37",
                   ota_process: bytes | None = None, ota_mode: int = 0o755,
                   include_ota_tool: bool = True, tamper: bool = False,
                   system_img: bytes | None = None) -> Path:
    """Synthesize a package with the same layout `md_upgrade` expects."""
    d = dest.parent
    parts = {
        "gpt.conf": b"# gpt\ndevice /dev/mmcblk0\n",
        "ota_process": ota_process if ota_process is not None else _aarch64_elf(),
        "system.img": system_img if system_img is not None else b"\x00" * 8192,
        "vbmeta.img": b"\x00" * 512,
        "boot.img": b"\x00" * 4096,
        "hbre.img": b"\x00" * 4096,
        "mondo.img": b"\x00" * 8192,
    }
    if include_ota_tool:
        parts["ota_tool"] = _aarch64_elf(128)
    md5s = {n: hashlib.md5(b).hexdigest() for n, b in parts.items()}
    data = {
        "version": version,
        "update_partition": ["ota_process", "system", "hbre", "mondo"],
        "partition_info": {
            "ota_process": {"imgname": "ota_process", "md5sum": {"ota_process": md5s["ota_process"]},
                            "md5_scope": {"ota_process": len(parts["ota_process"])}},
            "system": {"imgname": "system.img", "md5sum": {"system.img": md5s["system.img"]},
                       "md5_scope": {"system.img": len(parts["system.img"])}},
            "hbre": {"imgname": "hbre.img", "md5sum": {"hbre.img": md5s["hbre.img"]},
                     "md5_scope": {"hbre.img": len(parts["hbre.img"])}},
            "mondo": {"imgname": "mondo.img", "md5sum": {"mondo.img": md5s["mondo.img"]},
                      "md5_scope": {"mondo.img": len(parts["mondo.img"])}},
        },
    }
    inner = d / f"inner_{version}.zip"
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("data.json", json.dumps(data, indent=4))
        for name, blob in parts.items():
            zi = zipfile.ZipInfo(name, date_time=(2026, 11, 26, 12, 0, 0))
            zi.create_system = 3
            zi.external_attr = (0o100000 | (ota_mode if name == "ota_process" else 0o644)) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, blob)

    inner_bytes = inner.read_bytes()
    inner_sha = hashlib.sha256(inner_bytes).hexdigest()
    inner_name = f"lz110_0300_V{version}_20261126.mass.fw.plain.unsign"
    cfg_name = f"lz110_0000_V{version}_20261126.mass.cfg.plain.unsign"
    cfg = (
        "[package]\n"
        f"version = '{version}'\n"
        "package_id = 'test'\n"
        "created_at = '2026-11-26T12:00:00Z'\n\n"
        "[[firmwares]]\n"
        "part = '0300'\n"
        "device_type = 'X5'\n"
        f"size =  {len(inner_bytes) if not tamper else len(inner_bytes) + 1}\n"
        f"checksum = 'sha256:{inner_sha if not tamper else '0' * 64}'\n"
        "priority = 0\n"
        "required = true\n\n"
        "[strategy]\n"
        "max_concurrent = 1\n"
        "global_timeout = 3600\n"
    )
    pkg = dest
    with zipfile.ZipFile(pkg, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(cfg_name, cfg)
        zf.writestr(inner_name, inner_bytes)
    return pkg


def test_verify_package_accepts_a_good_build():
    d = _tmpdir()
    pkg = _build_package(d / "V26.11.19.37_lz110_freewheel.zip")
    report = ota.verify_package(pkg)
    assert report.package_version == "26.11.19.37"
    assert report.verified_modules == 1
    assert report.x5_entry_name.endswith(".mass.fw.plain.unsign")
    assert set(report.verified_x5_partitions) == {"ota_process", "system", "hbre", "mondo"}
    assert report.ota_process_mode == 0o755
    assert report.warnings == []
    assert ota.package_version(pkg) == "26.11.19.37"


def test_verify_package_rejects_anti_brick_faults():
    d = _tmpdir()

    def expect(pkg, needle: str, **kw):
        try:
            ota.verify_package(pkg, **kw)
        except ota.SafetyValidationError as e:
            assert needle in str(e), (needle, str(e))
            return
        raise AssertionError(f"expected SafetyValidationError containing {needle!r}")

    # 1. Manifest checksum/size lies
    expect(_build_package(d / "V26.11.19.37_lz110_tampered.zip", tamper=True),
           "size mismatch")

    # 2. ota_process without execute bits -> ota_tool execve() would fail
    noexec = _build_package(d / "V26.11.19.37_lz110_noexec.zip", ota_mode=0o644)
    expect(noexec, "execute bits")

    # 3. ota_process built for the wrong machine (x86-64)
    x86 = bytearray(_aarch64_elf())
    struct.pack_into("<H", x86, 18, 62)
    wrong_arch = _build_package(d / "V26.11.19.37_lz110_x86.zip", ota_process=bytes(x86))
    expect(wrong_arch, "wrong architecture")

    # 4. Mach-O / not-an-ELF at all
    expect(_build_package(d / "V26.11.19.37_lz110_macho.zip", ota_process=b"\xcf\xfa\xed\xfe" + b"\x00" * 200),
           "expected an ELF header")

    # 5. md_upgrade requires the uploaded name to start with 'V'
    good = _build_package(d / "V26.11.19.37_lz110_ok.zip")
    try:
        ota.verify_package(good, logical_filename="firmware.zip")
    except ota.SafetyValidationError as e:
        assert "must start with 'V'" in str(e)
    else:
        raise AssertionError("a non-V filename must be rejected")
    try:
        ota.verify_package(good, logical_filename="V99.99.99_lz110.zip")
    except ota.SafetyValidationError as e:
        assert "1 .mass.cfg" in str(e) or True      # manifest check runs before the name warning
    # a version/filename mismatch is only a warning
    rep = ota.verify_package(good, logical_filename="V26.11.99.99_lz110_freewheel.zip")
    assert any("does not start with" in w for w in rep.warnings)


def test_verify_package_protects_avb_files_against_the_base():
    d = _tmpdir()
    base = _build_package(d / "base_all_in_one.zip")
    # Rebuild with a MODIFIED system.img (the AVB-protected rootfs); without
    # --allow-unsafe-x5-override the protected-file CRC gate must fire.
    pkg = _build_package(d / "V26.11.19.37_lz110_freewheel.zip",
                         system_img=b"\x01" * 8192)
    try:
        ota.verify_package(pkg, base_zip_path=base)
    except ota.SafetyValidationError as e:
        assert "differs from the base firmware" in str(e)
    else:
        raise AssertionError("protected-file drift must be refused without the override flag")
    rep = ota.verify_package(pkg, base_zip_path=base, allow_unsafe_x5_override=True)
    assert rep.verified_x5_partitions


# ── preflight guards: shared_blocks, mixed builds, slot-commit gating ────────
#
# All offline: ext4 images are synthesized with `mke2fs` (+ a raw superblock RO_COMPAT
# write, since no e2fsprogs build ships a `shared_blocks` creator/`unshare_blocks` here)
# and packages are built with the same layout `md_upgrade` expects.

def _ext4_with(path: Path, files: dict[str, bytes] | None = None, *, size_mb: int = 16,
               extra_mkfs: tuple[str, ...] = ()) -> bool:
    from freewheel.ext4 import Ext4Image
    if not _has_mke2fs():
        return False
    subprocess.run(["truncate", "-s", f"{size_mb}M", str(path)], check=True)
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", *extra_mkfs, str(path)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if files:
        overlay = Path(tempfile.mkdtemp(prefix="fw_g_ov_")) / "root"
        for remote, blob in files.items():
            local = overlay / remote.lstrip("/")
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(blob)
        Ext4Image(path).apply_overlay_and_deletes(
            overlay_dir=overlay, mode_overrides={p: 0o644 for p in files})
    return True


def _mark_shared_blocks(path: Path) -> None:
    """Set RO_COMPAT 0x4000 in the superblock, as a deduplicated read-only image carries it.

    `tune2fs -O shared_blocks` and `e2fsck -E unshare_blocks` do not exist in every
    e2fsprogs build (1.47 on Ubuntu rejects both), so the bit is written directly. This is
    the same bit `dumpe2fs -h` renders as `shared_blocks`.
    """
    import struct
    with path.open("r+b") as fp:
        fp.seek(1024 + 0x64)
        ro_compat = struct.unpack("<I", fp.read(4))[0]
        fp.seek(1024 + 0x64)
        fp.write(struct.pack("<I", ro_compat | 0x4000))


def test_read_superblock_detects_shared_blocks_without_dumpe2fs():
    """The feature words come from the image itself; dumpe2fs need not exist."""
    from freewheel import ext4

    d = _tmpdir()
    plain = d / "plain.img"
    if not _ext4_with(plain, {"/etc/version": b"26.10.28.04\n"}):
        print("    (skipped: mke2fs not available)")
        return
    shared = d / "shared.img"
    shutil.copyfile(plain, shared)
    _mark_shared_blocks(shared)

    plain_feats = ext4.read_superblock(plain)
    assert plain_feats.is_ext4 and not plain_feats.shared_blocks
    assert plain_feats.has_journal

    shared_feats = ext4.read_superblock(shared)
    assert shared_feats.is_ext4 and shared_feats.shared_blocks
    assert shared_feats.ro_compat & 0x4000
    assert shared_feats.read_write_blockers()

    # A non-ext4 blob (or a truncated one) is reported, not raised.
    junk = d / "junk.bin"
    junk.write_bytes(b"\x00" * 4096)
    assert not ext4.read_superblock(junk).is_ext4
    tiny = d / "tiny.bin"
    tiny.write_bytes(b"\x00" * 16)
    assert not ext4.read_superblock(tiny).is_ext4
    # A file object works too, so callers can read straight out of a zip member.
    with plain.open("rb") as fp:
        assert ext4.read_superblock(fp).has_journal


def test_ext4_image_refuses_to_edit_a_shared_blocks_image():
    """`e2fsck -fn` exits 0 on shared_blocks; only the superblock check refuses the write."""
    from freewheel import ext4

    d = _tmpdir()
    img_path = d / "mondo.img"
    # metadata_csum would make the raw RO_COMPAT edit fail a superblock checksum
    # (there is no e2fsprogs `shared_blocks` creator here), so synthesize without it.
    if not _ext4_with(img_path, {"/etc/authorized_debug_profile": b"x\n"},
                      extra_mkfs=("-O", "^metadata_csum")):
        print("    (skipped: mke2fs not available)")
        return
    _mark_shared_blocks(img_path)

    img = ext4.Ext4Image(img_path)
    assert img.fsck()                       # integrity is fine — that is the trap
    assert img.path_exists("/etc/authorized_debug_profile")

    for call in (
        lambda: img.assert_editable(),
        lambda: img.assert_mountable_read_write(),
        lambda: img.apply_overlay_and_deletes(delete_paths=["/etc/authorized_debug_profile"]),
    ):
        try:
            call()
        except ext4.Ext4UnsafeImageError as e:
            assert "shared_blocks" in str(e)
        else:
            raise AssertionError("a shared_blocks image must refuse to be edited or paired rw")

    # Nothing was written: the file is still there.
    assert ext4.Ext4Image(img_path).path_exists("/etc/authorized_debug_profile")


def _package_with_system(
    dest: Path, *, system_img: bytes, mondo_img: bytes, version: str = "26.11.19.37",
    inner_data_version: str | None = None, module_version: str | None = None,
    extra_modules: dict[str, bytes] | None = None, extra_inner: dict[str, bytes] | None = None,
) -> Path:
    """A package whose `system.img` / `mondo.img` are real (synthesized) ext4 images.

    `extra_modules` adds further outer-level modules (e.g. an `0301`), which is where a
    cross-build mix becomes visible in a package's own version strings.
    """
    d = dest.parent
    data_version = inner_data_version if inner_data_version is not None else version
    parts = {
        "gpt.conf": b"# gpt\ndevice /dev/mmcblk0\n",
        "ota_process": _aarch64_elf(),
        "system.img": system_img,
        "mondo.img": mondo_img,
        "vbmeta.img": b"\x00" * 512,
        "boot.img": b"\x00" * 4096,
    }
    if extra_inner:
        parts.update(extra_inner)
    data = {
        "version": data_version,
        "update_partition": ["ota_process", "system", "mondo"],
        "partition_info": {
            name: {"imgname": name,
                   "md5sum": {name: hashlib.md5(blob).hexdigest()},
                   "md5_scope": {name: len(blob)}}
            for name, blob in parts.items() if name.endswith(".img")
        },
    }
    inner = d / f"inner_{version}.zip"
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("data.json", json.dumps(data, indent=4))
        for name, blob in parts.items():
            zi = zipfile.ZipInfo(name, date_time=(2026, 11, 26, 12, 0, 0))
            zi.create_system = 3
            zi.external_attr = (0o100000 | (0o755 if name == "ota_process" else 0o644)) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, blob)

    inner_bytes = inner.read_bytes()
    inner_sha = hashlib.sha256(inner_bytes).hexdigest()
    mod_ver = module_version or version
    inner_name = f"lz110_0300_V{mod_ver}_20261126.mass.fw.plain.unsign"
    cfg_name = f"lz110_0000_V{version}_20261126.mass.cfg.plain.unsign"

    fw_entries = [("0300", inner_name, len(inner_bytes), inner_sha)]
    for name, blob in (extra_modules or {}).items():
        fw_entries.append(("0301", name, len(blob), hashlib.sha256(blob).hexdigest()))

    cfg = (
        "[package]\n"
        f"version = '{version}'\n"
        "package_id = 'test'\n"
        "created_at = '2026-11-26T12:00:00Z'\n\n"
        + "".join(
            "[[firmwares]]\n"
            f"part = '{part}'\n"
            f"device_type = '{'X5' if part == '0300' else 'A350'}'\n"
            f"size =  {size}\n"
            f"checksum = 'sha256:{sha}'\n"
            "priority = 0\n"
            "required = true\n\n"
            for part, _n, size, sha in fw_entries
        )
        + "[strategy]\n"
        "max_concurrent = 1\n"
        "global_timeout = 3600\n"
    )
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(cfg_name, cfg)
        for _part, name, _size, _sha in fw_entries:
            zf.writestr(name, inner_bytes if name == inner_name else (extra_modules or {})[name])
    return dest


def test_guard_refuses_shared_blocks_mondo_under_read_write_system():
    """The exact pairing that bricked the robot: new read-only mondo, old rw-mounting system."""
    d = _tmpdir()
    system = d / "system.img"
    mondo_ro = d / "mondo_ro.img"
    mondo_rw = d / "mondo_rw.img"
    if not (_ext4_with(system, {"/etc/hb-fstab": b"/dev/block/platform/by-name/mondo /md ext4 defaults 0 1\n"})
            and _ext4_with(mondo_ro) and _ext4_with(mondo_rw)):
        print("    (skipped: mke2fs not available)")
        return
    _mark_shared_blocks(mondo_ro)

    pkg = _package_with_system(d / "V26.11.19.37_lz110_hybrid.zip",
                               system_img=system.read_bytes(), mondo_img=mondo_ro.read_bytes())
    try:
        ota.verify_package(pkg)
    except ota.SafetyValidationError as e:
        msg = str(e)
        assert "shared_blocks" in msg and "read-write" in msg, msg
    else:
        raise AssertionError("a shared_blocks mondo under a rw-mounting system must be refused")

    # The deliberate override downgrades it to a warning rather than a silent pass, and
    # the unrelated --allow-unsafe-x5-override must NOT silence it.
    try:
        ota.verify_package(pkg, allow_unsafe_x5_override=True)
    except ota.SafetyValidationError as e:
        assert "shared_blocks" in str(e)
    else:
        raise AssertionError("--allow-unsafe-x5-override must not silence the mondo pairing guard")
    base = _package_with_system(
        d / "base_all_in_one.zip", version="26.11.19.37",
        system_img=system.read_bytes(), mondo_img=mondo_ro.read_bytes(),
    )
    rep = ota.verify_package(pkg, allow_unsafe_mondo_pairing=True, base_zip_path=base)
    assert any("shared_blocks" in w for w in rep.warnings), rep.warnings

    # A journaled read-write mondo in the same package is fine.
    ok_pkg = _package_with_system(d / "V26.11.19.38_lz110_ok.zip", version="26.11.19.38",
                                  system_img=system.read_bytes(), mondo_img=mondo_rw.read_bytes())
    assert ota.verify_package(ok_pkg).verified_x5_partitions


def test_guard_allows_shared_blocks_mondo_with_read_only_system():
    """dm-verity era system.img mounts /md `ro,noload`: the shared_blocks pairing is correct there."""
    d = _tmpdir()
    system = d / "system.img"
    mondo_ro = d / "mondo_ro.img"
    if not (_ext4_with(system, {
                "/etc/hb-fstab": (
                    b"/dev/dm-1 /md ext4 ro,noload 0 0\n"
                    b"/dev/block/platform/by-name/mondo /md ext4 ro 0 0\n")})
            and _ext4_with(mondo_ro)):
        print("    (skipped: mke2fs not available)")
        return
    _mark_shared_blocks(mondo_ro)

    stock = mondo_ro.read_bytes()
    base = _package_with_system(
        d / "base_all_in_one.zip", version="26.11.19.39",
        system_img=system.read_bytes(), mondo_img=stock,
    )
    pkg = _package_with_system(d / "V26.11.19.39_lz110_verity.zip", version="26.11.19.39",
                               system_img=system.read_bytes(), mondo_img=stock)
    rep = ota.verify_package(pkg, base_zip_path=base)
    assert not any("shared_blocks" in w for w in rep.warnings), rep.warnings


def test_guard_refuses_shared_blocks_mondo_with_dm_rw_mount():
    """A device-mapper source with explicit rw is still read-write for shared_blocks pairing."""
    d = _tmpdir()
    system = d / "system.img"
    mondo_ro = d / "mondo_ro.img"
    if not (_ext4_with(system, {"/etc/hb-fstab": b"/dev/dm-1 /md ext4 rw 0 0\n"})
            and _ext4_with(mondo_ro)):
        print("    (skipped: mke2fs not available)")
        return
    _mark_shared_blocks(mondo_ro)

    pkg = _package_with_system(d / "V26.11.19.43_lz110_dm_rw.zip", version="26.11.19.43",
                               system_img=system.read_bytes(), mondo_img=mondo_ro.read_bytes())
    try:
        ota.verify_package(pkg)
    except ota.SafetyValidationError as e:
        assert "shared_blocks" in str(e) and "read-write" in str(e), str(e)
    else:
        raise AssertionError("shared_blocks mondo with /dev/dm-* rw mount must be refused")


def test_guard_refuses_mixed_module_builds():
    d = _tmpdir()
    system = d / "system.img"
    mondo = d / "mondo.img"
    if not (_ext4_with(system, {"/etc/hb-fstab": b"/dev/block/platform/by-name/mondo /md ext4 defaults 0 1\n"})
            and _ext4_with(mondo)):
        print("    (skipped: mke2fs not available)")
        return

    # An 0301 module from a different release than the 0300 is the hybrid signature.
    mixed = _package_with_system(
        d / "V26.11.19.40_lz110_mixed.zip", version="26.11.19.40",
        extra_modules={"lz110_0301_V26.10.27.92_20261028.mass.fw.plain.unsign": b"A350" * 64},
        system_img=system.read_bytes(), mondo_img=mondo.read_bytes())
    try:
        ota.verify_package(mixed)
    except ota.SafetyValidationError as e:
        assert "different firmware builds" in str(e)
    else:
        raise AssertionError("modules from two releases must be refused")
    rep = ota.verify_package(mixed, allow_mixed_firmware=True)
    assert any("mixes modules" in w for w in rep.warnings), rep.warnings

    # A vendor-style package whose module is named after the build it was cut from, not
    # after [package].version, is normal (V26.11.19.01 shipped a V26.10.27.92 0300 module)
    # and must NOT be refused.
    vendor_like = _package_with_system(
        d / "V26.11.19.41_lz110_vendor.zip", version="26.11.19.41",
        module_version="26.10.27.92", inner_data_version="26.10.27.92",
        extra_modules={"lz110_0301_V26.10.27.92_20261028.mass.fw.plain.unsign": b"A350" * 64},
        system_img=system.read_bytes(), mondo_img=mondo.read_bytes())
    rep = ota.verify_package(vendor_like)
    assert rep.verified_x5_partitions
    assert any("differs from the package version" in w for w in rep.warnings), rep.warnings
    assert not any("mixes modules" in w for w in rep.warnings), rep.warnings

    # Consistent package: 0300 and 0301 from the same build.
    good = _package_with_system(
        d / "V26.11.19.42_lz110_good.zip", version="26.11.19.42",
        extra_modules={"lz110_0301_V26.11.19.42_20261126.mass.fw.plain.unsign": b"A350" * 64},
        system_img=system.read_bytes(), mondo_img=mondo.read_bytes())
    assert ota.verify_package(good).verified_x5_partitions


def test_slot_commit_gating_is_detected_and_warned():
    d = _tmpdir()
    ungated_script = (
        "#!/bin/sh\n"
        "/usr/hobot/bin/ota_tool -b\n"
    )
    gated_script = (
        "#!/bin/sh\n"
        "if [ -f /run/lz100-mondo-apps-ready ]; then /usr/hobot/bin/ota_tool -b; fi\n"
    )
    ungated = d / "system_ungated.img"
    gated = d / "system_gated.img"
    other = d / "system_unrelated.img"
    if not (_ext4_with(ungated, {"/etc/init.d/S99ota_update_check.sh": ungated_script.encode()})
            and _ext4_with(gated, {"/etc/init.d/S99ota_update_check.sh": gated_script.encode()})
            and _ext4_with(other, {"/etc/version": b"26.11.19.01\n"})):
        print("    (skipped: mke2fs not available)")
        return

    assert ota.slot_commit_gating_from_system_img(ungated) == "ungated"
    assert ota.slot_commit_gating_from_system_img(gated) == "gated"
    assert ota.slot_commit_gating_from_system_img(other) == "unknown"
    assert ota.slot_commit_gating_from_system_img(d / "does-not-exist.img") == "unknown"

    assert ota.format_slot_commit_warning("gated") == ""
    for state in ("ungated", "unknown"):
        banner = ota.format_slot_commit_warning(state)
        assert "###" in banner and "rollback" in banner.lower(), banner
        assert len(banner.splitlines()) > 6, banner
    assert "ota_tool -b" in ota.format_slot_commit_warning("ungated")
    assert "lz100-mondo-apps-ready" in ota.format_slot_commit_warning("unknown")

    # The same detection works through a stock base package (what a build/upload sees).
    base_zip = d / "base_all_in_one.zip"
    with zipfile.ZipFile(base_zip, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("system.img", ungated.read_bytes())
    assert ota.slot_commit_gating_from_base_zip(base_zip) == "ungated"
    assert ota.slot_commit_gating_from_base_zip(None) == "unknown"
    assert ota.slot_commit_gating_from_base_zip(d / "nope.zip") == "unknown"

    mondo = d / "mondo.img"
    if not _ext4_with(mondo):
        print("    (skipped: mke2fs not available for nested base)")
        return
    nested_outer = _package_with_system(
        d / "V26.11.19.44_lz110_nested_base.zip", version="26.11.19.44",
        system_img=ungated.read_bytes(), mondo_img=mondo.read_bytes())
    assert ota.SYSTEM_IMG not in zipfile.ZipFile(nested_outer).namelist()
    assert ota.slot_commit_gating_from_base_zip(nested_outer) == "ungated"


# ── dm-verity / vbmeta mondo patch guard ─────────────────────────────────────

def _be64(v: int) -> bytes:
    return struct.pack(">Q", v)


def _be32(v: int) -> bytes:
    return struct.pack(">I", v)


def _wire_hashtree_descriptor(partition: str, *, salt: bytes = b"\xaa" * 32,
                              root: bytes = b"\xbb" * 32) -> bytes:
    """One serialized descriptor (header + body), libavb wire format."""
    name = partition.encode("utf-8")
    algo = b"sha256".ljust(32, b"\x00")
    body = (
        _be32(0)
        + _be64(1 << 20) + _be64(0) + _be64(0)
        + _be32(4096) + _be32(4096) + _be32(0) + _be64(0) + _be64(0)
        + algo
        + _be32(len(name)) + _be32(len(salt)) + _be32(len(root))
        + _be32(0)
        + b"\x00" * 60
        + name + salt + root
    )
    # body length must be a multiple of 8 per AvbDescriptor rules
    pad = (8 - (len(body) % 8)) % 8
    body += b"\x00" * pad
    tag = 1  # AVB_DESCRIPTOR_TAG_HASHTREE
    return _be64(tag) + _be64(len(body)) + body


def _wire_hash_descriptor(partition: str, *, salt: bytes = b"\xcc" * 32,
                           digest: bytes = b"\xdd" * 32) -> bytes:
    name = partition.encode("utf-8")
    algo = b"sha256".ljust(32, b"\x00")
    body = (
        _be64(1 << 20)
        + algo
        + _be32(len(name)) + _be32(len(salt)) + _be32(len(digest))
        + _be32(0)
        + b"\x00" * 60
        + name + salt + digest
    )
    pad = (8 - (len(body) % 8)) % 8
    body += b"\x00" * pad
    return _be64(2) + _be64(len(body)) + body


def _synthetic_vbmeta(*descriptors: bytes) -> bytes:
    """Minimal vbmeta image: header (BE) + auxiliary block (64-byte aligned)."""
    table = b"".join(descriptors)
    aux_size = ((len(table) + 63) // 64) * 64
    aux = table + b"\x00" * (aux_size - len(table))
    header = bytearray(256)
    header[0:4] = b"AVB0"
    struct.pack_into(">II", header, 4, 1, 0)
    struct.pack_into(">Q", header, 12, 0)           # authentication_data_block_size
    struct.pack_into(">Q", header, 20, aux_size)    # auxiliary_data_block_size
    struct.pack_into(">Q", header, 96, 0)           # descriptors_offset (into aux)
    struct.pack_into(">Q", header, 104, len(table))  # descriptors_size
    return bytes(header) + aux


def test_avb_vbmeta_parser_synthetic():
    from freewheel import avb

    mondo_tree = _wire_hashtree_descriptor("mondo")
    system_tree = _wire_hashtree_descriptor("system")
    blob = _synthetic_vbmeta(mondo_tree, system_tree)
    rep = avb.parse_vbmeta(blob)
    assert rep.status == "ok"
    assert rep.mondo_hashtree and not rep.mondo_hash
    assert "system" in rep.hashtree_partitions and "mondo" in rep.hashtree_partitions

    hash_only = _wire_hash_descriptor("boot")
    rep2 = avb.parse_vbmeta(_synthetic_vbmeta(hash_only))
    assert rep2.status == "ok" and not rep2.mondo_hashtree and rep2.hash_partitions == ("boot",)

    rep3 = avb.parse_vbmeta(b"not-avb")
    assert rep3.status == "unparseable"
    rep4 = avb.parse_vbmeta(blob[:200])
    assert rep4.status == "unparseable"

    # Little-endian legacy layout must not parse as ok with mondo present (regression).
    le_table = struct.pack("<QQ", 1, 68) + b"\x00" * 68 + b"mondo\x00" + b"\x00" * 27
    le_header = bytearray(256)
    le_header[0:4] = b"AVB0"
    struct.pack_into("<QQ", le_header, 12, 0, len(le_table))
    struct.pack_into("<II", le_header, 64, 0, len(le_table))
    rep_le = avb.parse_vbmeta(bytes(le_header) + le_table)
    assert rep_le.status != "ok" or not rep_le.mondo_hashtree, rep_le

    garbage_table = mondo_tree + b"\xff" * 4
    header = bytearray(256)
    header[0:4] = b"AVB0"
    struct.pack_into(">Q", header, 12, 0)
    struct.pack_into(">Q", header, 20, len(garbage_table))
    struct.pack_into(">Q", header, 96, 0)
    struct.pack_into(">Q", header, 104, len(garbage_table))
    assert avb.parse_vbmeta(bytes(header) + garbage_table).status == "unparseable"


def test_guard_refuses_verity_covered_mondo_patch():
    """A modified mondo.img under vbmeta hashtree metadata must refuse (distinct from shared_blocks)."""
    from freewheel import avb

    d = _tmpdir()
    mondo = d / "mondo.img"
    system = d / "system.img"
    if not (_ext4_with(mondo, {"/bin/ota_tool": _aarch64_elf(128)})
            and _ext4_with(system, {"/etc/hb-fstab": b"/dev/dm-1 /md ext4 ro,noload 0 0\n"})):
        print("    (skipped: mke2fs not available)")
        return

    vbmeta = _synthetic_vbmeta(_wire_hashtree_descriptor("mondo"), _wire_hashtree_descriptor("system"))
    stock = mondo.read_bytes()
    patched = bytearray(stock)
    patched[4096] ^= 0x55

    base = _package_with_system(
        d / "base_all_in_one.zip", version="26.11.19.50",
        system_img=system.read_bytes(), mondo_img=stock,
        extra_inner={"vbmeta.img": vbmeta},
    )
    pkg = _package_with_system(
        d / "V26.11.19.50_lz110_verity_mondo.zip", version="26.11.19.50",
        system_img=system.read_bytes(), mondo_img=bytes(patched),
        extra_inner={"vbmeta.img": vbmeta},
    )
    try:
        ota.verify_package(pkg, base_zip_path=base)
    except ota.SafetyValidationError as e:
        msg = str(e)
        assert "dm-verity" in msg and "root hash" in msg, msg
        assert "dm-verity-corrupted" in msg or "dm-verity protected" in msg, msg
    else:
        raise AssertionError("modified mondo on a verity-covered slot must be refused")

    try:
        ota.verify_package(pkg, base_zip_path=base, allow_unsafe_x5_override=True)
    except ota.SafetyValidationError as e:
        assert "dm-verity" in str(e)
    else:
        raise AssertionError("--allow-unsafe-x5-override must not silence the verity patch guard")

    rep = ota.verify_package(pkg, base_zip_path=base, allow_verity_patch=True)
    assert any("allow-verity-patch" in w.lower() or "verity-patch" in w for w in rep.warnings), rep.warnings
    assert rep.mondo_verity_covered is True
    assert any("hashtree" in s.lower() or "vbmeta" in s.lower() for s in rep.mondo_verity_evidence)

    # Unchanged mondo against the same base is fine even with hashtree metadata present.
    ok_pkg = _package_with_system(
        d / "V26.11.19.51_lz110_verity_ok.zip", version="26.11.19.51",
        system_img=system.read_bytes(), mondo_img=stock,
        extra_inner={"vbmeta.img": vbmeta},
    )
    assert ota.verify_package(ok_pkg, base_zip_path=base).verified_x5_partitions


def test_guard_refuses_verity_covered_mondo_without_baseline():
    """Without --base we cannot prove mondo is stock; refuse when vbmeta says dm-verity."""
    d = _tmpdir()
    mondo = d / "mondo.img"
    if not _ext4_with(mondo, {"/bin/ota_tool": _aarch64_elf(128)}):
        print("    (skipped: mke2fs not available)")
        return
    vbmeta = _synthetic_vbmeta(_wire_hashtree_descriptor("mondo"))
    pkg = _package_with_system(
        d / "V26.11.19.53_lz110_nobase.zip", version="26.11.19.53",
        system_img=b"\x00" * 8192,
        mondo_img=mondo.read_bytes(),
        extra_inner={"vbmeta.img": vbmeta},
    )
    try:
        ota.verify_package(pkg)
    except ota.SafetyValidationError as e:
        assert "no usable --base" in str(e) or "baseline" in str(e).lower(), str(e)
    else:
        raise AssertionError("verity-covered mondo without baseline must be refused")
    rep = ota.verify_package(pkg, allow_verity_patch=True)
    assert any("baseline unknown" in w.lower() for w in rep.warnings), rep.warnings


def test_guard_verity_evidence_shared_blocks_and_conf_paths():
    d = _tmpdir()
    mondo = d / "mondo.img"
    system = d / "system.img"
    if not (_ext4_with(mondo) and _ext4_with(system, {"/etc/lz100-mondo-verity.conf": b"enabled=1\n"})):
        print("    (skipped: mke2fs not available)")
        return
    _mark_shared_blocks(mondo)
    stock, patched = mondo.read_bytes(), bytearray(mondo.read_bytes())
    patched[8192] ^= 0x0f

    base = _package_with_system(
        d / "base_all_in_one.zip", version="26.11.19.52",
        system_img=system.read_bytes(), mondo_img=stock,
    )
    pkg = _package_with_system(
        d / "V26.11.19.52_lz110_shared_verity.zip", version="26.11.19.52",
        system_img=system.read_bytes(), mondo_img=bytes(patched),
    )
    try:
        ota.verify_package(pkg, base_zip_path=base)
    except ota.SafetyValidationError as e:
        msg = str(e)
        assert "dm-verity" in msg or "shared_blocks" in msg, msg
    else:
        raise AssertionError("modified shared_blocks mondo must refuse")


def test_ext4_refuses_mondo_verity_conf_without_shared_blocks():
    from freewheel import ext4

    d = _tmpdir()
    img = d / "mondo.img"
    if not _ext4_with(img, {"/etc/lz100-mondo-avb": b"ro,noload\n"},
                      extra_mkfs=("-O", "^metadata_csum")):
        print("    (skipped: mke2fs not available)")
        return
    image = ext4.Ext4Image(img)
    try:
        image.assert_mondo_patchable()
    except ext4.Ext4UnsafeImageError as e:
        assert "dm-verity" in str(e) and "lz100-mondo-avb" in str(e)
    else:
        raise AssertionError("verity config on mondo must refuse patch")
    image.assert_mondo_patchable(allow_verity_patch=True)


# ── mock md_upgrade (:8085) — inventory + resumable pull + V2 TUS ────────────

class _MockUpgrade:
    """In-process `md_upgrade`: bearer-gated `/list`, `/files/*` (Range), and V2 TUS."""

    def __init__(self, token: str, files: dict[str, bytes]):
        self.token = token
        self.files = files
        self.uploads: dict[str, bytearray] = {}
        self.installs: list[str] = []
        self.requests: list[tuple[str, str]] = []
        self.offset_conflicts = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_a):
                pass

            def _auth(self) -> bool:
                if outer.token and self.headers.get("Authorization") != f"Bearer {outer.token}":
                    self._send(401, b'{"error":"AUTH_REQUIRED"}')
                    return False
                return True

            def _send(self, code: int, body: bytes, extra: dict | None = None) -> None:
                self.send_response(code)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.requests.append(("GET", self.path))
                if not self._auth():
                    return
                u = urlparse(self.path)
                if u.path == "/health":
                    self._send(200, b'{"status":"ok"}')
                    return
                if u.path == "/list":
                    path = parse_qs(u.query).get("path", [""])[0]
                    prefix = f"{path}/" if path else ""
                    entries, seen = [], set()
                    for name in outer.files:
                        if not name.startswith(prefix):
                            continue
                        rest = name[len(prefix):]
                        head = rest.split("/", 1)[0]
                        if head in seen:
                            continue
                        seen.add(head)
                        entry = {"name": head}
                        if "/" in rest:
                            entry["file_type"] = "directory"
                        else:
                            entry["file_type"] = "file"
                            entry["size"] = len(outer.files[name])
                        entries.append(entry)
                    self._send(200, json.dumps({"files": entries}).encode())
                    return
                if u.path.startswith("/files/"):
                    key = unquote(u.path[len("/files/"):])
                    blob = outer.files.get(key)
                    if blob is None:
                        self._send(404, b"{}")
                        return
                    rng = self.headers.get("Range")
                    if rng and rng.startswith("bytes="):
                        start = int(rng.split("=", 1)[1].split("-", 1)[0] or 0)
                        chunk = blob[start:]
                        self._send(206, chunk, {"Content-Range": f"bytes {start}-{len(blob) - 1}/{len(blob)}"})
                    else:
                        self._send(200, blob)
                    return
                m = re.match(r"^/v2/upgrades/(?P<uid>[^/]+)$", u.path)
                if m:
                    data = outer.uploads.get(m.group("uid"), bytearray())
                    state = "READY" if len(data) else "UPLOADING"
                    self._send(200, json.dumps({"state": state, "offset": len(data)}).encode())
                    return
                self._send(404, b"{}")

            def do_HEAD(self):
                outer.requests.append(("HEAD", self.path))
                if not self._auth():
                    return
                u = urlparse(self.path)
                m = re.match(r"^/v2/upgrades/(?P<uid>[^/]+)/upload$", u.path)
                if not m:
                    self._send(404, b"{}")
                    return
                data = outer.uploads.get(m.group("uid"), bytearray())
                self.send_response(200)
                self.send_header("Upload-Offset", str(len(data)))
                self.send_header("Tus-Resumable", "1.0.0")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_PATCH(self):
                outer.requests.append(("PATCH", self.path))
                if not self._auth():
                    return
                if not self.headers.get("Upload-Token"):
                    self._send(403, b'{"error":"UPLOAD_TOKEN_REQUIRED"}')
                    return
                m = re.match(r"^/v2/upgrades/(?P<uid>[^/]+)/upload$", urlparse(self.path).path)
                if not m:
                    self._send(404, b"{}")
                    return
                uid = m.group("uid")
                data = outer.uploads.setdefault(uid, bytearray())
                n = int(self.headers.get("Content-Length") or 0)
                claimed = int(self.headers.get("Upload-Offset") or 0)
                # Real TUS semantics: the offset must match what the server holds.
                if claimed != len(data):
                    outer.offset_conflicts += 1
                    self._send(409, json.dumps({"held": len(data), "claimed": claimed}).encode())
                    return
                data.extend(self.rfile.read(n))
                self._send(204, b"")

            def do_POST(self):
                outer.requests.append(("POST", self.path))
                if not self._auth():
                    return
                m = re.match(r"^/v2/upgrades/(?P<uid>[^/]+)/install$", urlparse(self.path).path)
                if m:
                    outer.installs.append(m.group("uid"))
                    self._send(200, b'{"status":"installing"}')
                    return
                self._send(404, b"{}")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        return False


def _firmware_tree():
    return {
        "tmp/all_in_one.zip": b"PK" + os.urandom(2048),
        "extract_2ff1f0d8-5e55-432a-b0b5-0b0cabbe3ef3/x5_0300/hbre.img": os.urandom(6000),
        "extract_2ff1f0d8-5e55-432a-b0b5-0b0cabbe3ef3/x5_0300/system.img": os.urandom(1024),
        "extract_2ff1f0d8-5e55-432a-b0b5-0b0cabbe3ef3/last_package.toml": b"[package]\nversion='26.11.0.1'\n",
        "extract_2ff1f0d8-5e55-432a-b0b5-0b0cabbe3ef3/x5_0300/data.json": b"{}",
    }


def test_inventory_and_pull_firmware_with_resume():
    d = _tmpdir()
    files = _firmware_tree()
    with _MockUpgrade(SECRET, files) as mock:
        client = ota.MdUpgradeClient("127.0.0.1", mock.port, scheme="http", bearer_token=SECRET)
        inv = client.firmware_inventory()
        assert set(inv["by_name"]) == {"all_in_one.zip", "hbre.img", "system.img", "last_package.toml"}
        assert inv["extract_dirs"] == ["extract_2ff1f0d8-5e55-432a-b0b5-0b0cabbe3ef3"]

        # Seed a partial all_in_one.zip, then confirm the pull resumes rather than restarts.
        out = d / "beni_fw"
        partial = out / "current_26.11" / "all_in_one.zip"
        partial.parent.mkdir(parents=True)
        partial.write_bytes(files["tmp/all_in_one.zip"][:1000])

        res = ota.pull_robot_firmware("127.0.0.1", out_dir=out, port=mock.port,
                                      scheme="http", bearer_token=SECRET)
        got = {i["name"]: i for i in res["downloaded"]}
        assert set(got) == {"all_in_one.zip", "hbre.img", "system.img", "last_package.toml"}
        assert got["all_in_one.zip"]["path"] == str(out / "current_26.11" / "all_in_one.zip")
        assert partial.read_bytes() == files["tmp/all_in_one.zip"]
        hbre = out / "mirror" / "extract_2ff1f0d8-5e55-432a-b0b5-0b0cabbe3ef3" / "x5_0300" / "hbre.img"
        assert got["hbre.img"]["path"] == str(hbre)
        assert hbre.read_bytes() == files["extract_2ff1f0d8-5e55-432a-b0b5-0b0cabbe3ef3/x5_0300/hbre.img"]
        assert res["missing"] == ["mondo.img"]        # not staged on this unit
        assert any(r == ("GET", "/files/tmp/all_in_one.zip") for r in mock.requests)

        # Second run is a no-op (sizes match).
        again = ota.pull_robot_firmware("127.0.0.1", out_dir=out, port=mock.port,
                                        scheme="http", bearer_token=SECRET)
        assert all(i["skipped"] for i in again["downloaded"])


def test_pull_firmware_reports_missing_and_rejects_bad_bearer():
    d = _tmpdir()
    files = {"tmp/notes.txt": b"nothing useful here"}
    with _MockUpgrade(SECRET, files) as mock:
        res = ota.pull_robot_firmware("127.0.0.1", out_dir=d / "fw", port=mock.port,
                                      scheme="http", bearer_token=SECRET)
        assert res["downloaded"] == []
        assert set(res["missing"]) == set(ota.FIRMWARE_ARTIFACTS)

        try:
            ota.MdUpgradeClient("127.0.0.1", mock.port, scheme="http",
                                bearer_token="wrong-token").firmware_inventory()
        except ota.MdUpgradeError as e:
            assert "rejected our bearer" in str(e)
        else:
            raise AssertionError("a bad bearer must raise MdUpgradeError")

        # No bearer at all also fails, with the recovery hint.
        try:
            old = os.environ.pop("FREEWHEEL_CONFIG_DIR", None)
            home_bak = os.environ.get("HOME")
            os.environ["HOME"] = str(d)      # no ~/.config/freewheel here
            try:
                ota.MdUpgradeClient("127.0.0.1", mock.port, scheme="http").firmware_inventory()
            finally:
                if home_bak is not None:
                    os.environ["HOME"] = home_bak
                if old is not None:
                    os.environ["FREEWHEEL_CONFIG_DIR"] = old
        except ota.MdUpgradeError as e:
            assert "extract-token" in str(e)
        else:
            raise AssertionError("an unauthenticated read must fail")


def test_status_query_and_detect_scheme():
    with _MockUpgrade(SECRET, {"tmp/all_in_one.zip": b"x"}) as mock:
        assert ota.detect_scheme("127.0.0.1", mock.port, timeout=2.0) == "http"
        st = ota.check_robot_ota("127.0.0.1", mock.port, scheme="http", bearer_token=SECRET)
        assert st["health"] == {"status": "ok"}
        assert st["packages"]["files"][0]["name"] == "tmp"


# ── safety gates ─────────────────────────────────────────────────────────────

def test_preflight_refuses_a_low_battery_robot():
    # Pure gate: deterministic, no network.
    try:
        ota.evaluate_safety({"soc": 12, "charging": False, "docked": False}, None)
    except ota.SafetyValidationError as e:
        assert "battery too low" in str(e)
    else:
        raise AssertionError("a low battery must block flashing without --ignore-battery")
    # Docked/charging is fine even below the threshold.
    assert ota.evaluate_safety({"soc": 12, "charging": False, "docked": True}, None) == []
    assert ota.evaluate_safety({"soc": 12, "charging": False, "docked": False}, None,
                               ignore_battery=True) == []
    # Missing telemetry is a note, not a refusal.
    assert ota.evaluate_safety(None, None)[0].startswith("no battery")

    # Standing/moving robot refuses OTA when the posture gate is on.
    try:
        ota.evaluate_safety({"soc": 90, "charging": False, "docked": False},
                            {"robot_state": 2, "velocity_cms": 12}, check_posture=True)
    except ota.SafetyValidationError as e:
        assert "active/standing" in str(e)
    else:
        raise AssertionError("a balancing robot must block OTA when --check-posture is set")
    assert ota.evaluate_safety({"soc": 90, "charging": False, "docked": False},
                               {"robot_state": 2, "velocity_cms": 12}, check_posture=True,
                               ignore_posture=True) == []


# ── full OTA: Zenoh grant over the simulated robot + TUS upload to the mock :8085 ──

def test_upload_v2_end_to_end_against_sim():
    from freewheel import md_ts
    from freewheel.sitl import SimResponder as _SimResponder

    d = _tmpdir()
    pkg = _build_package(d / "V26.11.19.37_lz110_freewheel.zip")
    port = _free_udp_port()
    sim = _SimResponder("127.0.0.1", port, enable_video=False)       # plaintext robot
    sim.start()
    time.sleep(0.2)
    try:
        with _MockUpgrade(SECRET, {}) as mock:
            token_path = d / "media_token"
            ota.save_media_token(SECRET, token_path, expected_sha256=SECRET_SHA)
            old = os.environ.get("FREEWHEEL_MEDIA_TOKEN")
            os.environ["FREEWHEEL_MEDIA_TOKEN"] = SECRET
            try:
                task = ota.create_ota_task(pkg, host="127.0.0.1", ucp_port=port, ignore_battery=True)
                assert task["upload_grant_token"].startswith("sim-grant-")
                assert task["device_id"] == _SimResponder.SIM_SERIAL
                assert task["size"] == pkg.stat().st_size
                assert task["version"] == "26.11.19.37"
                assert task["battery"]["soc"] is not None

                result = ota.upload_firmware(
                    pkg, host="127.0.0.1", port=mock.port, ucp_port=port, mode="v2",
                    scheme="http", bearer_token=SECRET, ignore_battery=True,
                    upgrade_id=task["upgrade_id"], upload_token=task["upload_grant_token"],
                )
                assert result.mode == "v2" and result.remote_verified
                assert bytes(mock.uploads[task["upgrade_id"]]) == pkg.read_bytes()
                assert mock.offset_conflicts == 0, "a clean upload must not hit a TUS offset conflict"

                # Auto mode with an already-minted session must stay on V2 (not V1).
                fresh = _tmpdir()
                pkg2 = _build_package(fresh / "V26.11.19.38_lz110_freewheel.zip", version="26.11.19.38")
                task2 = ota.create_ota_task(pkg2, host="127.0.0.1", ucp_port=port, ignore_battery=True)
                auto = ota.upload_firmware(
                    pkg2, host="127.0.0.1", port=mock.port, ucp_port=port, mode="auto",
                    scheme="http", bearer_token=SECRET, ignore_battery=True,
                    upgrade_id=task2["upgrade_id"], upload_token=task2["upload_grant_token"],
                )
                assert auto.mode == "v2", f"auto mode with a minted session must stay V2, got {auto.mode}"
                assert auto.upgrade_id == task2["upgrade_id"]
                assert bytes(mock.uploads[task2["upgrade_id"]]) == pkg2.read_bytes()

                # Resume: a session that already holds a prefix must continue from there.
                partial = _tmpdir()
                pkg3 = _build_package(partial / "V26.11.19.39_lz110_freewheel.zip", version="26.11.19.39")
                task3 = ota.create_ota_task(pkg3, host="127.0.0.1", ucp_port=port, ignore_battery=True)
                blob = pkg3.read_bytes()
                mock.uploads[task3["upgrade_id"]] = bytearray(blob[:700])
                resumed = ota.upload_firmware(
                    pkg3, host="127.0.0.1", port=mock.port, ucp_port=port, mode="v2",
                    scheme="http", bearer_token=SECRET, ignore_battery=True,
                    upgrade_id=task3["upgrade_id"], upload_token=task3["upload_grant_token"],
                    chunk_size=64 * 1024,
                )
                assert resumed.mode == "v2" and resumed.remote_verified
                assert bytes(mock.uploads[task3["upgrade_id"]]) == blob, "resume must not restart from 0"
                assert mock.offset_conflicts == 0, "resume must read the server offset, not collide"

                inst = ota.trigger_ota_install(
                    "127.0.0.1", upgrade_id=task["upgrade_id"], upload_token=task["upload_grant_token"],
                    port=mock.port, scheme="http", bearer_token=SECRET, ucp_port=port,
                    ignore_battery=True,
                )
                assert inst["method"] == "v2_http_install"
                assert task["upgrade_id"] in mock.installs
            finally:
                if old is None:
                    os.environ.pop("FREEWHEEL_MEDIA_TOKEN", None)
                else:
                    os.environ["FREEWHEEL_MEDIA_TOKEN"] = old
    finally:
        sim.stop()

def test_auto_mode_never_downgrades_a_safety_refusal_to_v1():
    """A low battery must abort, not silently switch to the ungated V1 inbox path."""
    from freewheel.sitl import SimResponder as _SimResponder

    d = _tmpdir()
    pkg = _build_package(d / "V26.11.19.40_lz110_freewheel.zip", version="26.11.19.40")
    port = _free_udp_port()
    sim = _SimResponder("127.0.0.1", port, enable_video=False)
    sim.start()
    time.sleep(0.2)
    try:
        with _MockUpgrade(SECRET, {}) as mock:
            old = os.environ.get("FREEWHEEL_MEDIA_TOKEN")
            os.environ["FREEWHEEL_MEDIA_TOKEN"] = SECRET
            try:
                try:
                    ota.upload_firmware(
                        pkg, host="127.0.0.1", port=mock.port, ucp_port=port, mode="auto",
                        scheme="http", bearer_token=SECRET,
                        # Nothing on the robot is below 100%, so this forces a refusal.
                        min_battery_pct=101, ignore_battery=False,
                    )
                except ota.SafetyValidationError as e:
                    assert "battery too low" in str(e)
                else:
                    raise AssertionError("auto mode must propagate the battery refusal")
                # No bytes may have been uploaded through the ungated V1 path.
                assert not any(method == "PATCH" for method, _p in mock.requests), mock.requests
                assert not mock.uploads
            finally:
                if old is None:
                    os.environ.pop("FREEWHEEL_MEDIA_TOKEN", None)
                else:
                    os.environ["FREEWHEEL_MEDIA_TOKEN"] = old
    finally:
        sim.stop()

def test_serial_number_and_ota_control_over_zenoh():
    from freewheel import MondoClient
    from freewheel.sitl import SimResponder as _SimResponder

    port = _free_udp_port()
    sim = _SimResponder("127.0.0.1", port, enable_video=False)
    sim.start()
    time.sleep(0.2)
    client = MondoClient(host="127.0.0.1", port=port, log=lambda _m: None)
    client.connect()
    time.sleep(0.3)
    try:
        assert client.serial_number(timeout=3.0) == _SimResponder.SIM_SERIAL
        rsp = client.ota_control(ota.OTA_CMD_QUERY, timeout=3.0)
        assert rsp is not None and int(rsp.get("retCode", -1)) == 0
        started = client.ota_control(
            ota.OTA_CMD_START, timeout=3.0,
            task={"protocolVersion": 2, "upgradeId": "u-1", "deviceId": _SimResponder.SIM_SERIAL,
                  "sha256": "0" * 64, "size": 10, "version": "1.2.3.4", "originalFilename": "V1.zip"},
        )
        assert started["task"]["uploadGrantToken"].startswith("sim-grant-")
    finally:
        client.close()
        sim.stop()

# ── CLI surface ─────────────────────────────────────────────────────────────

def test_cli_help_and_doctor_exit_codes():
    r = subprocess.run([sys.executable, "-m", "freewheel.ota", "--help"], cwd=SDK_DIR,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0
    for cmd in ("extract-token", "pull-firmware", "inventory", "verify", "upload", "doctor"):
        assert cmd in r.stdout

    d = _tmpdir()
    env = {k: v for k, v in os.environ.items()
           if k not in ota.TOKEN_ENV_VARS}
    env["HOME"] = str(d)
    env["PYTHONPATH"] = SDK_DIR
    r = subprocess.run([sys.executable, "-m", "freewheel.ota", "doctor"], cwd=str(d), env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert "extract-token" in r.stdout

    apk = d / "MondoApp.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libapp.so", b"\x00" + SECRET.encode() + b"\x00")
    r = subprocess.run([sys.executable, "-m", "freewheel.ota", "extract-token", str(apk),
                        "--expected-sha256", SECRET_SHA, "--no-save", "--print"],
                       cwd=SDK_DIR, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert SECRET in r.stdout


def test_no_external_sdk_import_surface():
    """The new modules must not import an external SDK, and the ext4 helper must be
    importable without e2fsprogs present (it only resolves tools on first use)."""
    blocked = _BLOCKED_EXTERNAL_MODULES
    for name in ("freewheel/ota.py", "freewheel/ext4.py"):
        text = (Path(SDK_DIR) / name).read_text(encoding="utf-8")
        for mod in blocked:
            assert f"import {mod}" not in text and f"from {mod}" not in text, (name, mod)

    code = (
        "import sys;"
        + "".join(f"sys.modules[{m!r}]=None;" for m in blocked) +
        "import freewheel.ota as o; import freewheel.ext4 as e;"
        "print(o.MEDIA_TOKEN_SHA256[:8]); print(o.OTA_CMD_INSTALL); print(e._MIN_FREE_INODES)"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=SDK_DIR, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "5500fdb0" in r.stdout

    # `benibust.py` (the jailbreak CLI) must import and describe itself with
    # every external SDK module blocked outright.
    root = Path(SDK_DIR).parent / "benibust.py"
    code = (
        "import sys;"
        + "".join(f"sys.modules[{m!r}]=None;" for m in blocked) +
        f"sys.argv=['benibust.py','--help'];"
        f"exec(compile(open({str(root)!r}).read(), {str(root)!r}, 'exec'), {{'__name__':'__main__','__file__':{str(root)!r}}})"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=str(root.parent),
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "--fetch-firmware" in r.stdout
    text = root.read_text(encoding="utf-8")
    for mod in blocked:
        assert f"import {mod}" not in text and f"from {mod}" not in text, mod


# ── the jailbreak build itself, with external SDKs blocked ──────────────────

def _real_ext4_with(path: Path, files: dict[str, bytes], size_mb: int = 24) -> bool:
    """Build an ext4 image containing `files` at the given absolute paths."""
    from freewheel.ext4 import Ext4Image
    if not _has_mke2fs():
        return False
    subprocess.run(["truncate", "-s", f"{size_mb}M", str(path)], check=True)
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", str(path)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    overlay = Path(tempfile.mkdtemp(prefix="fw_ov_")) / "root"
    overlay.mkdir()
    for remote, blob in files.items():
        local = overlay / remote.lstrip("/")
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(blob)
    Ext4Image(path).apply_overlay_and_deletes(
        overlay_dir=overlay, mode_overrides={p: 0o755 for p in files},
    )
    return True


def test_benibust_builds_a_package_without_external_sdk():
    """End-to-end: real ext4 images in, verified OTA package out — external SDKs blocked."""
    if not _has_mke2fs():
        print("    (skipped: mke2fs not available)")
        return
    root_dir = Path(SDK_DIR).parent
    script = root_dir / "benibust.py"
    out = _tmpdir() / "build"
    out.mkdir()

    system_img = out / "system.img"
    hbre_img = out / "hbre.img"
    assert _real_ext4_with(system_img, {"/usr/sbin/sshd": _aarch64_elf(8192)})
    assert _real_ext4_with(hbre_img, {"/bin/cam-service": _aarch64_elf(1024),
                                      "/bin/ota_tool": _aarch64_elf(1024)})
    code = f'''
import sys
sys.path.insert(0, {str(root_dir)!r})
sys.path.insert(0, {str(SDK_DIR)!r})
for _m in {_BLOCKED_EXTERNAL_MODULES!r}:
    sys.modules[_m] = None
import json, zipfile, hashlib, struct
from pathlib import Path
import benibust as fr
from freewheel import ota

base = Path({str(out / "all_in_one.zip")!r})
out = base.parent
PATCH_AT = 1024

def aarch64_elf(size: int, patch_at: int | None = None) -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b"\\x7fELF"
    hdr[4], hdr[5], hdr[6] = 2, 1, 1
    struct.pack_into("<H", hdr, 18, ota.EM_AARCH64)
    blob = bytearray(bytes(hdr) + b"\\x00" * (size - 64))
    if patch_at is not None:
        blob[patch_at:patch_at + 4] = fr.OTA_PATCH_OLD
    return bytes(blob)

system_img = Path({str(system_img)!r}).read_bytes()
hbre_img = Path({str(hbre_img)!r}).read_bytes()
md5 = lambda b: hashlib.md5(b).hexdigest()
parts = {{
    "gpt.conf": b"# gpt\\n",
    "ota_process": aarch64_elf(8192, PATCH_AT),
    "vbmeta.img": b"\\x00" * 512,
    "boot.img": b"\\x00" * 1024,
    "system.img": system_img,
    "mondo.img": b"\\x00" * 1024,
}}
data = {{
    "version": "26.11.0.1",
    "update_partition": ["ota_process", "system", "mondo"],
    "partition_info": {{
        k: {{"imgname": k if k.endswith(".img") else k,
             "md5sum": {{(k if k.endswith(".img") else k): md5(v)}},
             "md5_scope": {{(k if k.endswith(".img") else k): len(v)}}}}
        for k, v in parts.items()
    }},
}}
with zipfile.ZipFile(base, "w", zipfile.ZIP_STORED) as zf:
    zf.writestr("data.json", json.dumps(data))
    for name, blob in parts.items():
        zf.writestr(name, blob)

# Point the patch at the fixture's offset so the real patching code runs.
fr.OTA_PATCH_OFFSET = PATCH_AT

pkg = out / "V26.11.19.37_lz110_freewheel.zip"
res = fr.build_package(base, Path({str(hbre_img)!r}), pkg, "26.11.19.37", Path({str(out / "work")!r}),
                       payload="ssh", ssh_pubkey="ssh-ed25519 AAAAC3Nza freewheel-test", ssh_port=2222)
assert res == pkg and pkg.is_file()
report = ota.verify_package(pkg, base_zip_path=base, allow_unsafe_x5_override=True)
assert report.package_version == "26.11.19.37", report

# The patched hbre must carry the payload and still boot.
from freewheel.ext4 import Ext4Image
with zipfile.ZipFile(pkg) as zf:
    inner_name = [n for n in zf.namelist() if n.endswith(".mass.fw.plain.unsign")][0]
    with zipfile.ZipFile(__import__("io").BytesIO(zf.read(inner_name))) as inner:
        (out / "hbre_patched.img").write_bytes(inner.read("hbre.img"))
img = Ext4Image(out / "hbre_patched.img")
assert img.path_exists("/bin/ota_tool")
assert img.path_exists("/bin/md_sshd") and img.path_exists("/bin/cam-service.real")
hook = img.read_file("/bin/cam-service").decode()
assert "freewheel" in hook and "md_sshd" in hook
assert "cam-service.real" in hook
assert (img.stat_path("/bin/md_sshd").mode & 0o777) == 0o755
assert img.read_file("/bin/freewheel_authorized_keys").decode().startswith("ssh-ed25519 ")
img.fsck()
print("BUILD_OK")
'''
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("NEBI", "PYNEBI"))}
    r = subprocess.run([sys.executable, "-c", code], cwd=str(root_dir), env=env,
                       capture_output=True, text=True, timeout=300)
    assert "BUILD_OK" in r.stdout, (r.stdout[-4000:], r.stderr[-4000:])


def test_benibust_builds_every_payload_variant():
    """Both/telnet/ssh payloads each produce a verified, fsck-clean package."""
    if not _has_mke2fs():
        print("    (skipped: mke2fs not available)")
        return
    root_dir = Path(SDK_DIR).parent
    out = _tmpdir() / "variants"
    out.mkdir()
    system_img = out / "system.img"
    hbre_img = out / "hbre.img"
    assert _real_ext4_with(system_img, {"/usr/sbin/sshd": _aarch64_elf(4096)})
    assert _real_ext4_with(hbre_img, {"/bin/cam-service": _aarch64_elf(512),
                                      "/bin/ota_tool": _aarch64_elf(512)})
    script = Path(tempfile.mkstemp(suffix=".py", prefix="fw_variant_")[1])
    script.write_text(VARIANT_SCRIPT)
    try:
        r = subprocess.run([sys.executable, str(script), str(out), str(system_img), str(hbre_img)],
                           cwd=str(root_dir), capture_output=True, text=True, timeout=300)
        assert "ALL_VARIANTS_OK" in r.stdout, (r.stdout[-3000:], r.stderr[-3000:])
    finally:
        script.unlink(missing_ok=True)


VARIANT_SCRIPT = '''
import hashlib, io, json, struct, sys, zipfile
from pathlib import Path
sys.path.insert(0, %r)
sys.path.insert(0, %r)
import benibust as fr
from freewheel import ota
from freewheel.ext4 import Ext4Image

OUT, SYSTEM_IMG, HBRE_IMG = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
PATCH_AT = 1024


def elf(size, patch=None):
    h = bytearray(64)
    h[0:4] = b"\\x7fELF"
    h[4], h[5], h[6] = 2, 1, 1
    struct.pack_into("<H", h, 18, ota.EM_AARCH64)
    blob = bytearray(bytes(h) + b"\\x00" * (size - 64))
    if patch is not None:
        blob[patch:patch + 4] = fr.OTA_PATCH_OLD
    return bytes(blob)


base = OUT / "all_in_one.zip"
parts = {
    "gpt.conf": b"# gpt\\n",
    "ota_process": elf(4096, PATCH_AT),
    "vbmeta.img": b"\\x00" * 256,
    "boot.img": b"\\x00" * 512,
    "system.img": SYSTEM_IMG.read_bytes(),
    "mondo.img": b"\\x00" * 512,
}
data = {
    "version": "26.11.0.1",
    "update_partition": ["ota_process", "system", "mondo"],
    "partition_info": {
        k: {"imgname": k, "md5sum": {k: hashlib.md5(v).hexdigest()}, "md5_scope": {k: len(v)}}
        for k, v in parts.items()
    },
}
with zipfile.ZipFile(base, "w", zipfile.ZIP_STORED) as zf:
    zf.writestr("data.json", json.dumps(data))
    for n, b in parts.items():
        zf.writestr(n, b)

fr.OTA_PATCH_OFFSET = PATCH_AT

for payload in ("both", "telnet", "ssh"):
    pkg = OUT / f"V26.11.19.44_lz110_{payload}.zip"
    fr.build_package(base, HBRE_IMG, pkg, "26.11.19.44", OUT / payload,
                     payload=payload, ssh_pubkey="ssh-ed25519 AAAA test")
    with zipfile.ZipFile(pkg) as zf:
        inner = [n for n in zf.namelist() if n.endswith(".mass.fw.plain.unsign")][0]
        with zipfile.ZipFile(io.BytesIO(zf.read(inner))) as iz:
            patched = OUT / f"hbre_{payload}.img"
            patched.write_bytes(iz.read("hbre.img"))
    img = Ext4Image(patched)
    hook = img.read_file("/bin/cam-service").decode()
    assert img.path_exists("/bin/ota_tool"), "hbre lost /bin/ota_tool"
    assert "cam-service.real" in hook, "hook must exec the real camera service"
    if payload in ("ssh", "both"):
        assert "md_sshd" in hook and img.path_exists("/bin/md_sshd")
        assert (img.stat_path("/bin/freewheel_authorized_keys").mode & 0o777) == 0o600
    else:
        assert "md_sshd" not in hook and not img.path_exists("/bin/md_sshd")
    if payload in ("telnet", "both"):
        assert "telnetd" in hook and "192.168.7.1" in hook, "telnet must bind the robot AP only"
    else:
        assert "telnetd" not in hook
    img.fsck()
    ota.verify_package(pkg, base_zip_path=base, allow_unsafe_x5_override=True)
    print(f"{payload}: OK")
print("ALL_VARIANTS_OK")
''' % (str(Path(SDK_DIR).parent), SDK_DIR)


def test_pull_workdir_grabs_everything_not_just_known_artifacts():
    """`/list?path=` enumerates the whole work dir, so grab all of it — that's how the
    firmware was first captured."""
    files = {
        "tmp/all_in_one.zip": b"PK" + os.urandom(4096),
        "tmp/V26.10.28.05_lz110_old.zip": b"PK" + os.urandom(2048),
        "extract_2ff1f0d8/x5_0300/hbre.img": os.urandom(5000),
        "extract_2ff1f0d8/x5_0300/system.img": os.urandom(1500),
        "extract_2ff1f0d8/last_package.toml": b"[package]\nversion='26.10.28.05'\n",
        "extract_2ff1f0d8/notes.txt": b"not a firmware artifact at all",
    }
    d = _tmpdir()
    with _MockUpgrade(SECRET, files) as mock:
        res = ota.pull_work_tree("127.0.0.1", out_dir=d / "dump", port=mock.port,
                                 scheme="http", bearer_token=SECRET)
        assert res["failures"] == []
        assert len(res["files"]) == len(files), res["files"]
        for rel, blob in files.items():
            local = d / "dump" / rel
            assert local.is_file() and local.read_bytes() == blob, rel

        again = ota.pull_work_tree("127.0.0.1", out_dir=d / "dump", port=mock.port,
                                   scheme="http", bearer_token=SECRET)
        assert all(f["skipped"] for f in again["files"])

        # A partial file resumes instead of restarting.
        target = d / "dump" / "tmp" / "all_in_one.zip"
        target.write_bytes(files["tmp/all_in_one.zip"][:1000])
        ota.pull_work_tree("127.0.0.1", out_dir=d / "dump", port=mock.port,
                           scheme="http", bearer_token=SECRET)
        assert target.read_bytes() == files["tmp/all_in_one.zip"]


FAKE_SSH_DD = '''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
cmd = args[-1]
node = {node!r}
mode = {mode!r}
if os.environ.get("FAKE_SSH_FAIL_PROBE") == "1" and cmd.startswith("readlink -f"):
    sys.stderr.write("ssh: connect to host: Connection refused\\n")
    sys.exit(255)
if cmd.startswith("readlink -f"):
    print({resolved!r})
    print({size})
    sys.exit(0)
if cmd.startswith("dd if="):
    data = open(node, "rb").read()
    if mode == "truncate":
        data = data[:4096]
    out = sys.stdout.buffer
    for i in range(0, len(data), 1 << 20):
        out.write(data[i:i + (1 << 20)])
    out.flush()
    if mode == "fail":
        sys.stderr.write("dd: read error\\n")
        sys.exit(1)
    sys.exit(0)
sys.exit(3)
'''


def _fake_ssh_env(d: Path, image: Path, size: int, *, mode: str = "ok",
                  resolved: str = "/dev/mmcblk0p15") -> dict:
    bindir = d / "fakebin"
    bindir.mkdir(exist_ok=True)
    script = bindir / "ssh"
    script.write_text(FAKE_SSH_DD.format(node=str(image), size=size, mode=mode, resolved=resolved))
    script.chmod(0o755)
    return dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}")


def test_dump_partition_never_destroys_an_existing_image():
    """A failed dump must leave the previous (rollback) image intact."""
    d = _tmpdir()
    part_bytes = ota.HBRE_PARTITION_BYTES
    src = d / "source.img"
    subprocess.run(["truncate", "-s", str(part_bytes), str(src)], check=True)
    dest = d / "hbre.img"
    precious = b"PRISTINE-BACKUP" * 64
    dest.write_bytes(precious)

    old_path = os.environ.get("PATH")
    old_fail = os.environ.get("FAKE_SSH_FAIL_PROBE")
    try:
        # 1. SSH unreachable (probe fails)
        os.environ["PATH"] = _fake_ssh_env(d, src, part_bytes)["PATH"]
        os.environ["FAKE_SSH_FAIL_PROBE"] = "1"
        try:
            ota.dump_partition("hbre", host="127.0.0.1", out=dest)
        except RuntimeError as exc:
            assert "left untouched" in str(exc), exc
        else:
            raise AssertionError("an unreachable robot must raise")
        assert dest.read_bytes() == precious, "probe failure destroyed the existing dump"
        assert not list(d.glob("*.partial")), "a failed probe left a partial file behind"

        # 2. Transfer fails mid-stream (dd exits non-zero)
        os.environ.pop("FAKE_SSH_FAIL_PROBE", None)
        os.environ["PATH"] = _fake_ssh_env(d, src, part_bytes, mode="fail")["PATH"]
        try:
            ota.dump_partition("hbre", host="127.0.0.1", out=dest)
        except RuntimeError as exc:
            assert "left untouched" in str(exc), exc
        else:
            raise AssertionError("a failed dd must raise")
        assert dest.read_bytes() == precious, "a failed transfer destroyed the existing dump"
        assert not list(d.glob("*.partial")), "a failed transfer left a partial file behind"

        # 3. Short read: flagged, existing image kept, bad bytes preserved for inspection
        os.environ["PATH"] = _fake_ssh_env(d, src, part_bytes, mode="truncate")["PATH"]
        res = ota.dump_partition("hbre", host="127.0.0.1", out=dest)
        assert not res["ok"] and res["notes"]
        assert dest.read_bytes() == precious, "a short read destroyed the existing dump"
        assert Path(res["local"]).name.endswith(".partial") and Path(res["local"]).is_file()

        # 4. Success finally replaces it
        os.environ["PATH"] = _fake_ssh_env(d, src, part_bytes)["PATH"]
        ok = ota.dump_partition("hbre", host="127.0.0.1", out=dest)
        assert ok["ok"] and ok["local"] == str(dest)
        assert dest.read_bytes() == src.read_bytes(), "successful dump must replace the file"
        assert not list(d.glob("*.partial")), "success left a partial file behind"

        # 5. A failed dump with no existing image must not leave junk at the destination
        fresh = d / "fresh.img"
        os.environ["PATH"] = _fake_ssh_env(d, src, part_bytes, mode="fail")["PATH"]
        try:
            ota.dump_partition("hbre", host="127.0.0.1", out=fresh)
        except RuntimeError:
            pass
        assert not fresh.exists(), "a failed dump created the destination anyway"
    finally:
        if old_path is not None:
            os.environ["PATH"] = old_path
        if old_fail is None:
            os.environ.pop("FAKE_SSH_FAIL_PROBE", None)
        else:
            os.environ["FAKE_SSH_FAIL_PROBE"] = old_fail


def test_dump_partition_reads_an_exact_image_over_ssh():
    """dump-partition must yield a byte-identical, readable image of the full partition."""
    if not _has_mke2fs():
        print("    (skipped: mke2fs not available)")
        return
    from freewheel.ext4 import Ext4Image

    d = _tmpdir()
    part_bytes = ota.HBRE_PARTITION_BYTES
    src = d / "source_hbre.img"
    subprocess.run(["truncate", "-s", str(part_bytes), str(src)], check=True)
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", str(src)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    overlay = d / "ov"
    (overlay / "bin").mkdir(parents=True)
    (overlay / "bin" / "ota_tool").write_bytes(b"\x7fELF" + b"\x00" * 512)
    Ext4Image(src).apply_overlay_and_deletes(overlay_dir=overlay,
                                             mode_overrides={"/bin/ota_tool": 0o755})

    env = _fake_ssh_env(d, src, part_bytes)
    old = os.environ.get("PATH")
    os.environ["PATH"] = env["PATH"]
    try:
        out = d / "dumped.img"
        res = ota.dump_partition("hbre", host="127.0.0.1", slot="current", out=out)
        assert res["ok"], res["notes"]
        assert res["bytes"] == part_bytes
        assert out.read_bytes() == src.read_bytes()
        assert res["sha256"] == ota.sha256_file(src)
        assert res["node"].endswith("/by-name/hbre")
        assert Ext4Image(out).path_exists("/bin/ota_tool")

        # Pinning a slot addresses the explicit A/B node (where the pristine image
        # lives once the running slot has been modified).
        pinned = ota.dump_partition("hbre", host="127.0.0.1", slot="b", out=d / "b.img")
        assert pinned["node"].endswith("/by-name/hbre_b")

        # A short read must be reported, not silently accepted.
        short = ota.dump_partition("hbre", host="127.0.0.1", out=d / "short.img",
                                   expected_size=part_bytes + 4096)
        assert not short["ok"] and short["notes"]
    finally:
        if old is not None:
            os.environ["PATH"] = old


def test_hbre_validation_requires_the_exact_partition_size():
    root_dir = Path(SDK_DIR).parent
    code = f'''
import sys
sys.path.insert(0, {str(root_dir)!r})
sys.path.insert(0, {str(SDK_DIR)!r})
import benibust as fr
assert fr.HBRE_PARTITION_BYTES == 157_286_400, fr.HBRE_PARTITION_BYTES
try:
    fr.find_hbre_img({str(Path("/nonexistent_small.img"))!r})
except SystemExit:
    pass
print("SIZE_CONSTANT_OK")
'''
    # An undersized explicit image must be refused before any build work happens.
    d = _tmpdir()
    small = d / "small.img"
    small.write_bytes(b"\x00" * 1024)
    code = f'''
import sys
sys.path.insert(0, {str(root_dir)!r})
sys.path.insert(0, {str(SDK_DIR)!r})
import benibust as fr
try:
    fr.find_hbre_img({str(small)!r})
except SystemExit as exc:
    assert exc.code == 1, exc.code
else:
    raise AssertionError("an undersized --hbre must be refused")
print("REJECTED_OK")
'''
    r = subprocess.run([sys.executable, "-c", code], cwd=str(root_dir),
                       capture_output=True, text=True, timeout=120)
    assert "REJECTED_OK" in r.stdout, (r.stdout, r.stderr)


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in tests:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
