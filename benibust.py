#!/usr/bin/env python3
"""BeniBust: owner root for Beni/Mondo X5 robots (right-to-repair jailbreak).

Builds an OTA package that installs a key-only root SSH server via the unsigned
hbre partition (with an AP-only telnet fallback), uploads it, triggers the OTA,
and verifies access. Owner-initiated, reversible, and built from firmware you
supply — no vendor images or secrets are bundled.

Modes:
    benibust.py                    # build + flash + verify
    benibust.py --scan             # read-only device scan
    benibust.py --shell            # connect to an existing root channel
    benibust.py --restore PKG      # flash a stock vendor package (rollback)
    benibust.py --dry-run          # build only, do not flash
    benibust.py --skip-build PKG   # flash a pre-built package
    benibust.py --fetch-firmware   # pull your own images off the robot first

Payloads:
    --payload both   key-only sshd on :2222 + AP-only telnet fallback (default)
    --payload ssh    key-only sshd only (no telnet)
    --payload telnet AP-only telnet only

The SSH key defaults to ~/.ssh/freewheel_ed25519 (created if missing). Telnet,
when enabled, binds only to the robot AP (192.168.7.1:23/:2323).

Requires: this repo's `sdk/` (bundled — no pip installs), `e2fsprogs`, `ssh-keygen`,
and (for a secure_v2 robot) the `cryptography` package. You need two artifacts off
your own hardware, and BeniBust can now fetch both:

    python3 benibust.py --fetch-firmware     # all_in_one.zip + hbre.img from your robot
    python3 -m freewheel.ota extract-token ~/Downloads/MondoApp.apk   # your media bearer

Neither a third-party SDK nor its patch tool is required. See BENIBUST.md §"Getting
your own key and firmware" for the full walkthrough.

For personally-owned devices only. See BENIBUST.md for scope, disclosure, and
restore guidance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

# The SDK lives next to this script; make `freewheel` importable without an install
# so `python3 benibust.py` works straight out of a clone.
_SDK_DIR = Path(__file__).resolve().parent / "sdk"
if _SDK_DIR.is_dir() and str(_SDK_DIR) not in sys.path:
    sys.path.insert(0, str(_SDK_DIR))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OTA_PATCH_OFFSET = 35364
OTA_PATCH_OLD = bytes.fromhex("2a020054")  # b.ge 0x408a68
OTA_PATCH_NEW = bytes.fromhex("11000014")  # b    0x408a68  (unconditional)

DEFAULT_SSH_KEY = Path.home() / ".ssh" / "freewheel_ed25519"
TELNET_AP = "192.168.7.1"


def _ota():
    """Import `freewheel.ota` lazily so `--help` works without optional deps."""
    from freewheel import ota
    return ota


def _ext4_mod():
    from freewheel import ext4
    return ext4


def sshd_config(ssh_port: int) -> str:
    return f"""Port {ssh_port}
ListenAddress 0.0.0.0
HostKey /private/freewheel/ssh_host_ed25519_key
HostKey /private/freewheel/ssh_host_rsa_key
AuthorizedKeysFile /private/freewheel/authorized_keys
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes yes
PidFile /private/freewheel/sshd.pid
Subsystem sftp internal-sftp
"""


def build_wrapper(payload: str, ssh_port: int) -> bytes:
    lines = [
        "#!/bin/sh",
        "# BeniBust hbre boot hook (owner root; right-to-repair).",
        "",
    ]
    if payload in ("ssh", "both"):
        lines += [
            "mkdir -p /private/freewheel /run/sshd /var/empty 2>/dev/null",
            "chmod 700 /private/freewheel 2>/dev/null",
            "chmod 755 /var/empty 2>/dev/null",
            "cp /usr/hobot/bin/freewheel_authorized_keys /private/freewheel/authorized_keys 2>/dev/null",
            "chmod 600 /private/freewheel/authorized_keys 2>/dev/null",
            "if [ ! -f /private/freewheel/ssh_host_ed25519_key ]; then",
            "  LD_LIBRARY_PATH=/lib:/usr/lib /usr/bin/ssh-keygen -t ed25519 -f /private/freewheel/ssh_host_ed25519_key -N '' >/dev/null 2>&1",
            "  LD_LIBRARY_PATH=/lib:/usr/lib /usr/bin/ssh-keygen -t rsa -b 3072 -f /private/freewheel/ssh_host_rsa_key -N '' >/dev/null 2>&1",
            "fi",
            "if [ -x /usr/hobot/bin/md_sshd ]; then",
            "  echo \"$(date) freewheel: starting md_sshd\" >>/tmp/freewheel_sshd.log 2>/dev/null",
            "  LD_LIBRARY_PATH=/lib:/usr/lib /usr/hobot/bin/md_sshd -f /usr/hobot/bin/freewheel_sshd_config >>/tmp/freewheel_sshd.log 2>&1",
            "fi",
            "",
        ]
    if payload in ("telnet", "both"):
        lines += [
            "# AP-only telnet fallback (join Beni-xxxxxx)",
            "{",
            f"  /bin/busybox telnetd -b {TELNET_AP} -p 23 -l /bin/sh",
            f"  /bin/busybox telnetd -b {TELNET_AP} -p 2323 -l /bin/sh",
            "} >/dev/null 2>&1 &",
            "",
        ]
    lines += [
        'echo "freewheel-hook" > /tmp/hbre_hook 2>/dev/null || true',
        'exec /usr/hobot/bin/cam-service.real "$@"',
        "",
    ]
    return "\n".join(lines).encode()


def ensure_ssh_key(path: Path) -> str:
    path = path.expanduser()
    pub = Path(str(path) + ".pub")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        step(f"Generating SSH key {path}")
        r = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(path), "-N", "", "-C", "benibust"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            die(f"ssh-keygen failed: {(r.stderr or r.stdout).strip()}")
    if pub.exists():
        return pub.read_text().strip()
    r = subprocess.run(["ssh-keygen", "-y", "-f", str(path)], capture_output=True, text=True)
    if r.returncode != 0:
        die(f"cannot read public key {pub}: {(r.stderr or r.stdout).strip()}")
    return r.stdout.strip()


def extract_sshd(base_zip: Path, work_dir: Path) -> Path:
    """Extract /usr/sbin/sshd from the user's own system.img for the hbre payload."""
    ext4 = _ext4_mod()
    ota = _ota()
    system_img = work_dir / "system.img"
    step("Extracting /usr/sbin/sshd from your system.img")
    with zipfile.ZipFile(base_zip, "r") as z:
        with z.open("system.img") as src, system_img.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
    img = ext4.Ext4Image(system_img)
    out = work_dir / "md_sshd"
    img.dump_file_to("/usr/sbin/sshd", out)
    os.chmod(out, 0o755)
    ota.verify_aarch64_elf_header(out.read_bytes()[:64], "hbre.img:/bin/md_sshd")
    system_img.unlink(missing_ok=True)
    return out


KNOWN_BASE_LOCATIONS = [
    Path("beni_fw/current_26.11/all_in_one.zip"),
    Path.home() / "Documents/beni_firmware/base_v26.11/all_in_one.zip",
]

# The hbre partition is a fixed 150 MiB slot; md_upgrade writes and md5-checks the whole
# range, so an image must be exactly this size.
HBRE_PARTITION_BYTES = 157_286_400


def find_hbre_candidates() -> list[Path]:
    """Every plausible stock `hbre.img` under the usual firmware roots."""
    found: list[Path] = []
    for root in (Path("beni_fw"), Path.home() / "Documents/beni_firmware"):
        if root.is_dir():
            found.extend(sorted(root.rglob("hbre.img")))
    return found

ROBOT_AP_IP = "192.168.7.1"
TELNET_PORTS = [23, 2323]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_file(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: Path) -> str:
    return _hash_file(path, "md5")


def md5_file_and_size(path: Path) -> tuple[str, int]:
    return _hash_file(path, "md5"), path.stat().st_size


def sha256_file(path: Path) -> str:
    return _hash_file(path, "sha256")


def add_stream(zf: zipfile.ZipFile, arcname: str, src_fp, size: int,
               mode: int = 0o644, compress=zipfile.ZIP_DEFLATED):
    zi = zipfile.ZipInfo(arcname, date_time=(2026, 11, 25, 12, 0, 0))
    zi.compress_type = compress
    zi.create_system = 3
    zi.external_attr = (mode & 0o7777) << 16
    zi.file_size = size
    with zf.open(zi, "w", force_zip64=True) as dst:
        shutil.copyfileobj(src_fp, dst, length=1 << 20)


def tcp_check(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def progress_bar(current: int, total: int):
    pct = current / total * 100 if total else 0
    mb = current / (1024 * 1024)
    total_mb = total / (1024 * 1024)
    bar_len = 30
    filled = int(bar_len * current / total) if total else 0
    bar = "=" * filled + "-" * (bar_len - filled)
    print(f"\r  [{bar}] {pct:5.1f}%  {mb:.0f}/{total_mb:.0f} MB", end="", flush=True)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def find_base_zip(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            die(f"Base firmware not found: {p}")
        return p
    for loc in KNOWN_BASE_LOCATIONS:
        if loc.is_file():
            return loc
    die(
        "Could not find V26.11 all_in_one.zip.\n"
        "  Pull it off your own robot (USB-C 192.168.123.1 or AP 192.168.7.1):\n"
        "      python3 benibust.py --fetch-firmware\n"
        "  or supply it with --base PATH, or place it at:\n"
        f"    {KNOWN_BASE_LOCATIONS[0]}"
    )


def find_hbre_img(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_file():
            die(f"hbre.img not found: {p}")
        size = p.stat().st_size
        if size < HBRE_PARTITION_BYTES:
            die(
                f"hbre.img at {p} is {size:,} bytes; the hbre partition is {HBRE_PARTITION_BYTES:,}.\n"
                "  md_upgrade writes and md5-checks the full partition range, so a short image is\n"
                "  rejected on-device. Re-dump the whole partition:\n"
                f"    dd if=/dev/block/platform/by-name/hbre of=hbre.img bs=1M count={HBRE_PARTITION_BYTES // (1 << 20)}"
            )
        if size > HBRE_PARTITION_BYTES:
            warn(f"hbre.img at {p} is {size:,} bytes — larger than the {HBRE_PARTITION_BYTES:,} partition; "
                 "the tail will be ignored")
        return p
    candidates = find_hbre_candidates()
    exact = [p for p in candidates if p.stat().st_size == HBRE_PARTITION_BYTES]
    if exact:
        return exact[0]
    if candidates:
        # Anything else is a warning: it may still be right for a different revision.
        warn(f"no hbre.img at the expected {HBRE_PARTITION_BYTES:,} bytes; using {candidates[0]} "
             f"({candidates[0].stat().st_size:,} bytes)")
        return candidates[0]
    die(
        "Could not find hbre.img.\n"
        "  Best source: dump the partition off your own robot (needs a root shell):\n"
        "      python3 -m freewheel.ota dump-partition hbre --host <robot-ip>\n"
        "  Without root, pull the copy md_upgrade already staged:\n"
        "      python3 benibust.py --fetch-firmware\n"
        "  Or supply it with --hbre PATH (it also ships inside a vendor V26.09 package,\n"
        "  in the 0300 inner zip)."
    )


def discover_robot(explicit: str | None) -> str:
    if explicit:
        return explicit
    # Try robot AP first
    if tcp_check(ROBOT_AP_IP, 8085, timeout=2):
        return ROBOT_AP_IP
    info("Robot not found at AP (192.168.7.1). Scanning local subnet...")
    # Try common DHCP IPs
    for last_octet in [52, 58, 60, 100, 101]:
        ip = f"192.168.68.{last_octet}"
        if tcp_check(ip, 8085, timeout=1):
            return ip
    die(
        "Could not discover robot. Supply its IP with --host.\n"
        "  On robot AP: 192.168.7.1\n"
        "  On home WiFi: check your router for the robot's DHCP lease."
    )


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_package(base_zip: Path, hbre_img: Path, output: Path,
                  version: str, work_dir: Path, *, payload: str = "both",
                  ssh_pubkey: str = "", ssh_port: int = 2222) -> Path:
    """Build the v15-style OTA package: stock verity images + patched hbre + patched ota_process."""

    stage = work_dir / "stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    step("Opening base firmware")
    with zipfile.ZipFile(base_zip, "r") as z:
        names = set(z.namelist())
        for req in ("data.json", "gpt.conf", "ota_process", "vbmeta.img",
                     "boot.img", "system.img", "mondo.img"):
            if req not in names:
                die(f"Base firmware missing required file: {req}")

        # 1. Patch ota_process
        step("Patching ota_process (allowlist bypass at 0x408a24)")
        op = z.read("ota_process")
        if op[OTA_PATCH_OFFSET:OTA_PATCH_OFFSET + 4] != OTA_PATCH_OLD:
            die(
                f"Unexpected bytes at ota_process offset {OTA_PATCH_OFFSET}: "
                f"{op[OTA_PATCH_OFFSET:OTA_PATCH_OFFSET+4].hex()} "
                f"(expected {OTA_PATCH_OLD.hex()}). Wrong firmware version?"
            )
        patched_op = bytearray(op)
        patched_op[OTA_PATCH_OFFSET:OTA_PATCH_OFFSET + 4] = OTA_PATCH_NEW
        (stage / "ota_process").write_bytes(patched_op)
        os.chmod(stage / "ota_process", 0o755)
        ok("ota_process: b.ge -> b (unconditional)")

        # 2. Build patched hbre.img
        step(f"Patching hbre.img ({payload} payload)")
        hbre_path = stage / "hbre.img"
        shutil.copyfile(hbre_img, hbre_path)

        img = _ext4_mod().Ext4Image(hbre_path)
        overlay = stage / "overlay"
        (overlay / "bin").mkdir(parents=True)

        img.dump_file_to("/bin/cam-service", overlay / "bin" / "cam-service.real")
        os.chmod(overlay / "bin" / "cam-service.real", 0o755)

        mode_overrides = {"/bin/cam-service": 0o755, "/bin/cam-service.real": 0o755}
        if payload in ("ssh", "both"):
            if not ssh_pubkey:
                die("SSH payload requested but no public key was provided")
            sshd = extract_sshd(base_zip, work_dir)
            shutil.copyfile(sshd, overlay / "bin" / "md_sshd")
            os.chmod(overlay / "bin" / "md_sshd", 0o755)
            (overlay / "bin" / "freewheel_authorized_keys").write_text(ssh_pubkey.strip() + "\n")
            (overlay / "bin" / "freewheel_sshd_config").write_text(sshd_config(ssh_port))
            mode_overrides["/bin/md_sshd"] = 0o755
            mode_overrides["/bin/freewheel_authorized_keys"] = 0o600
            mode_overrides["/bin/freewheel_sshd_config"] = 0o600

        (overlay / "bin" / "cam-service").write_bytes(build_wrapper(payload, ssh_port))
        os.chmod(overlay / "bin" / "cam-service", 0o755)

        changes = img.apply_overlay_and_deletes(
            overlay_dir=overlay,
            mode_overrides=mode_overrides,
            verify_readback=True,
        )
        img.fsck()

        if not img.path_exists("/bin/ota_tool"):
            die("hbre lost /bin/ota_tool — image corruption")
        if payload in ("ssh", "both") and not img.path_exists("/bin/md_sshd"):
            die("hbre md_sshd missing")
        ok(f"hbre.img: {payload} payload installed ({changes})")

        # 3. Update data.json: add hbre and refresh every checksum we invalidated
        step("Updating data.json (hbre partition + patched-image checksums)")
        hbre_size = hbre_path.stat().st_size
        data = json.loads(z.read("data.json").decode("utf-8"))
        if "hbre" not in data["update_partition"]:
            idx = data["update_partition"].index("mondo")
            data["update_partition"].insert(idx, "hbre")
        data["partition_info"]["hbre"] = {
            "md5sum": {"hbre.img": md5_file(hbre_path)},
            "md5_scope": {"hbre.img": hbre_size},
            "medium": "emmc",
            "part_type": "AB",
            "upgrade_method": "image",
            "imgname": "hbre.img",
        }
        # Patching ota_process invalidates the scope MD5 the stock data.json carries;
        # md_upgrade verifies it on-device, so recompute it from the file we ship.
        replaced = {"ota_process": stage / "ota_process", "hbre.img": hbre_path}
        for part_name, meta in data.get("partition_info", {}).items():
            imgname = meta.get("imgname")
            if imgname in replaced:
                digest, size = md5_file_and_size(replaced[imgname])
                meta.setdefault("md5sum", {})[imgname] = digest
                meta.setdefault("md5_scope", {})[imgname] = size
        (stage / "data.json").write_text(json.dumps(data, indent=4) + "\n")
        (stage / "gpt.conf").write_bytes(z.read("gpt.conf"))
        ok(f"data.json: partitions = {data['update_partition']}")

        # 4. Pack inner zip (0300 x5 firmware)
        step("Packing inner firmware archive")
        date_str = time.strftime("%Y%m%d")
        inner_name = f"lz110_0300_V{version}_{date_str}.mass.fw.plain.unsign"
        inner_path = stage / inner_name

        order = ["data.json", "gpt.conf", "ota_process", "vbmeta.img",
                 "boot.img", "system.img", "hbre.img", "mondo.img"]
        with zipfile.ZipFile(inner_path, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=1, allowZip64=True) as zo:
            for name in order:
                if name in ("data.json", "gpt.conf", "ota_process"):
                    src = stage / name
                    with src.open("rb") as f:
                        m = 0o755 if name == "ota_process" else 0o644
                        c = zipfile.ZIP_DEFLATED if src.stat().st_size < (16 << 20) else zipfile.ZIP_STORED
                        add_stream(zo, name, f, src.stat().st_size, m, c)
                elif name == "hbre.img":
                    with hbre_path.open("rb") as f:
                        add_stream(zo, name, f, hbre_size, 0o644, zipfile.ZIP_DEFLATED)
                else:
                    zi_src = z.getinfo(name)
                    with z.open(name, "r") as f:
                        add_stream(zo, name, f, zi_src.file_size, 0o644, zipfile.ZIP_DEFLATED)

        inner_size = inner_path.stat().st_size
        inner_sha = sha256_file(inner_path)
        ok(f"inner: {inner_name} ({inner_size / 1e6:.1f} MB)")

        # 5. Write manifest
        step("Writing TOML manifest")
        cfg_name = f"lz110_0000_V{version}_{date_str}.mass.cfg.plain.unsign"
        cfg_text = f"""[package]
version = '{version}'
package_id = 'benibust_{date_str}'
created_at = '{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}'

[[firmwares]]
part = '0300'
device_type = 'X5'
size =  {inner_size}
checksum = 'sha256:{inner_sha}'
priority = 0
required = true

[strategy]
max_concurrent = 1
global_timeout = 3600
"""
        (stage / cfg_name).write_text(cfg_text)
        ok(f"manifest: V{version}")

        # 6. Pack outer zip
        step("Packing outer OTA package")
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zo:
            cfg_p = stage / cfg_name
            with cfg_p.open("rb") as f:
                add_stream(zo, cfg_name, f, cfg_p.stat().st_size, 0o644, zipfile.ZIP_STORED)
            with inner_path.open("rb") as f:
                add_stream(zo, inner_name, f, inner_size, 0o644, zipfile.ZIP_STORED)

        pkg_size = output.stat().st_size
        ok(f"package: {output.name} ({pkg_size / 1e6:.1f} MB)")

    # 7. Verify
    step("Verifying package integrity")
    if not output.name.startswith("V"):
        warn(f"Output filename {output.name!r} should start with 'V{version}_' for md_upgrade")

    # Slot-commit gating is a property of the firmware the package is built from, so
    # it is checkable at build time — before anything touches the robot.
    gate = _ota().slot_commit_gating_from_base_zip(base_zip)
    banner = gate and _ota().format_slot_commit_warning(gate)
    if banner:
        print(banner)
    try:
        report = _ota().verify_package(
            output,
            base_zip_path=base_zip,
            allow_unsafe_x5_override=True,
            logical_filename=f"V{version}_lz110_benibust.zip",
        )
        for w in report.warnings:
            warn(w)
        if report.mondo_verity_covered is not None:
            state = "covered" if report.mondo_verity_covered else "not covered"
            detail = "; ".join(report.mondo_verity_evidence) if report.mondo_verity_evidence else "no signals"
            info(f"mondo dm-verity: {state} ({detail})")
            if report.mondo_verity_vbmeta_status:
                info(f"vbmeta: {report.mondo_verity_vbmeta_status}")
        ok(f"verified: {report.verified_modules} module(s), "
           f"partitions {report.verified_x5_partitions}")
    except Exception as e:
        die(f"package verification failed: {e}")

    return output


# ---------------------------------------------------------------------------
# Upload, install, monitor
# ---------------------------------------------------------------------------

def upload_package(pkg_path: Path, host: str, base_zip_path: Path | None = None) -> dict:
    step(f"Uploading to {host} via TUS (this takes a few minutes)")
    info("Close the Mondo app first — UCP is single-session.")

    result = _ota().upload_firmware(
        pkg_path,
        host=host,
        mode="v2",
        ignore_battery=True,
        max_retries=3,
        timeout=600.0,
        chunk_size=4 * 1024 * 1024,
        progress=progress_bar,
        log=lambda m: info(m),
        base_zip_path=base_zip_path,
        # BeniBust patches ota_process by design, so the protected-file CRC gate is
        # expected to fire; the mondo pairing and mixed-module gates are NOT overridden.
        allow_unsafe_x5_override=True,
    )
    print()  # newline after progress bar
    ok(f"uploaded: {result.mode}, upgrade_id={result.upgrade_id}")
    for w in result.warnings:
        warn(w)
    return {"upgrade_id": result.upgrade_id, "upload_token": result.upload_token}


def install_ota(host: str, upgrade_id: str, upload_token: str) -> dict:
    step("Triggering OTA install")
    result = _ota().trigger_ota_install(
        host,
        upgrade_id=upgrade_id,
        upload_token=upload_token,
        ignore_battery=True,
        ignore_posture=True,
        timeout=15.0,
        log=lambda m: info(m),
    )
    ok(f"install triggered: {result.get('method', '?')}")
    return result


def monitor_ota(host: str, timeout_sec: int = 300) -> bool:
    step("Monitoring OTA progress (robot will reboot)")

    t0 = time.time()
    last_state = ""
    while time.time() - t0 < timeout_sec:
        try:
            status = _ota().check_robot_ota(host, timeout=3.0)
            packages = status.get("packages", {})
            if isinstance(packages, dict):
                state = packages.get("state", packages.get("body", ""))
            else:
                state = str(packages)

            if state != last_state:
                info(f"OTA state: {state}")
                last_state = state

            if "SUCCEEDED" in str(state).upper():
                ok("OTA install succeeded")
                return True

        except Exception:
            elapsed = time.time() - t0
            if elapsed > 30:
                info(f"Robot unreachable ({elapsed:.0f}s) — likely rebooting...")
            time.sleep(5)
            continue

        time.sleep(5)

    warn(f"Monitoring timed out after {timeout_sec}s")
    return False


def _ssh_base(host: str, key: Path, port: int) -> list[str]:
    return [
        "ssh", "-p", str(port), "-i", str(key.expanduser()),
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=6", f"root@{host}",
    ]


def ssh_ok(host: str, key: Path, port: int) -> bool:
    try:
        r = subprocess.run(_ssh_base(host, key, port) + ["id"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and "uid=0" in r.stdout


def verify_root(host: str, ssh_port: int = 2222, ssh_key: Path = DEFAULT_SSH_KEY,
                retries: int = 12, delay: float = 10.0) -> bool:
    step(f"Verifying root on {host}")
    for attempt in range(retries):
        if tcp_check(host, ssh_port, timeout=3.0) and ssh_ok(host, ssh_key, ssh_port):
            ok(f"key-only SSH root on :{ssh_port}")
            print()
            print("  " + "=" * 60)
            print("  BENIBUST ROOT ACHIEVED")
            print()
            print(f"    ssh -p {ssh_port} -i {Path(ssh_key).expanduser()} root@{host}")
            print()
            print("  " + "=" * 60)
            return True
        for port in TELNET_PORTS:
            if tcp_check(host, port, timeout=2.0):
                ok(f"telnet fallback responding on :{port} (AP only)")
                print()
                print(f"    python3 -c 'import telnetlib,time; "
                      f"t=telnetlib.Telnet(\"{host}\",{port},timeout=10); "
                      f"time.sleep(.5); t.interact()'")
                return True
        if attempt < retries - 1:
            remaining = (retries - attempt - 1) * delay
            info(f"Not yet... retrying ({remaining:.0f}s remaining)")
            time.sleep(delay)

    warn("No root channel found. The robot may still be booting, or you may need")
    warn("to reconnect to the robot AP (Beni-xxxxxx) and use the AP-only telnet fallback.")
    return False


def scan_robot(host: str) -> int:
    step(f"Scanning {host} (read-only)")
    for port in (8085, 8010, 22, 2222, 23, 2323):
        info(f"tcp/{port}: {'open' if tcp_check(host, port, 1.5) else 'closed'}")
    try:
        status = _ota().check_robot_ota(host, timeout=4.0)
        info(f"OTA status: {status}")
    except Exception as e:  # noqa: BLE001
        info(f"OTA query unavailable: {type(e).__name__}: {e}")
    try:
        ota = _ota()
        if not ota.resolve_media_token():
            warn("no media token yet — python -m freewheel.ota extract-token <MondoApp.apk>")
    except Exception:  # noqa: BLE001
        pass
    if tcp_check(host, 2222, 1.5):
        ok("SSH root channel present (:2222) — try --shell")
    elif any(tcp_check(host, p, 1.5) for p in TELNET_PORTS):
        ok("AP-only telnet fallback present (:23/:2323) — try --shell")
    return 0


def fetch_firmware(host: str | None, out_dir: str = "beni_fw") -> int:
    """Pull the owner's own `all_in_one.zip` + `hbre.img` off the robot's `:8085` daemon."""
    ota = _ota()
    if not ota.resolve_media_token():
        warn("No media token found — the robot's :8085 read endpoints need it.")
        info("Recover it from your own copy of the app (verified against the digest "
             "the robot checks):")
        info("  python -m freewheel.ota extract-token ~/Downloads/MondoApp.apk")
        return 1
    target = host or discover_robot(None)
    step(f"Looking for staged firmware on {target} (:8085)")
    info("This reads md_upgrade's work dir — the same images an OTA just installed.")

    def _progress(name: str, done: int, total: int) -> None:
        if name != getattr(_progress, "name", None):
            print()
            _progress.name = name  # type: ignore[attr-defined]
            info(f"pulling {name}")
        progress_bar(done, total)

    try:
        res = ota.pull_robot_firmware(target, out_dir=out_dir, progress=_progress)
    except ota.MdUpgradeError as e:
        print()
        die(str(e))
    print()
    for item in res["downloaded"]:
        ok(f"{'have' if item['skipped'] else 'pulled'} {item['name']} -> {item['path']}")
    if res["missing"]:
        warn(f"not staged on this unit: {', '.join(res['missing'])}")
        info("md_upgrade keeps the outer archive under tmp/ only until the next update.")
        info("Fallback: capture an app-driven update with `python -m freewheel.fwextract`.")
    if not res["downloaded"]:
        warn("Nothing to pull. Try the capture fallback documented in BENIBUST.md.")
        return 1
    return 0


def connect_shell(host: str, ssh_key: Path, ssh_port: int) -> int:
    if tcp_check(host, ssh_port, 2.0):
        cmd = [
            "ssh", "-p", str(ssh_port), "-i", str(ssh_key.expanduser()),
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            f"root@{host}",
        ]
        info("Opening SSH shell: " + " ".join(cmd))
        os.execvp(cmd[0], cmd)
    for port in TELNET_PORTS:
        if tcp_check(host, port, 2.0):
            info(f"Opening telnet fallback on :{port}")
            try:
                import telnetlib
            except ImportError:
                die("telnetlib unavailable (Python 3.13+). Use the 3.11 venv.")
            t = telnetlib.Telnet(host, port, timeout=10)
            time.sleep(0.5)
            t.interact()
            return 0
    die("No root channel on :2222/:23/:2323. Is BeniBust installed and the robot reachable?")


def backup_state(host: str, ssh_key: Path, ssh_port: int, outdir: str) -> int:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    step(f"Backing up device state to {out}")
    cmds = {
        "version": "cat /etc/version; echo; cat /proc/cmdline",
        "mounts": "cat /proc/mounts",
        "dm": "dmsetup table 2>/dev/null; dmsetup status 2>/dev/null",
        "ps": "ps -ef",
        "last_package": "cat /blackbox/firmware/last_package.toml 2>/dev/null",
        "private_version": "cat /private/version.toml 2>/dev/null",
        "freewheel": "ls -l /private/freewheel 2>/dev/null; cat /tmp/hbre_hook 2>/dev/null",
    }
    for name, cmd in cmds.items():
        try:
            r = subprocess.run(_ssh_base(host, ssh_key, ssh_port) + [cmd], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as e:
            warn(f"{name}: {e}")
            continue
        if r.returncode == 0:
            (out / f"{name}.txt").write_text(r.stdout)
            ok(f"{name}.txt")
        else:
            warn(f"{name}: {(r.stderr or r.stdout).strip()}")
    warn("State snapshot only (not full partition images). Keep a vendor full package for restore.")
    return 0


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def step(msg: str):
    print(f"\n\033[1;37m>>> {msg}\033[0m")

def ok(msg: str):
    print(f"  \033[32m[+]\033[0m {msg}")

def info(msg: str):
    print(f"  \033[36m[*]\033[0m {msg}")

def warn(msg: str):
    print(f"  \033[33m[!]\033[0m {msg}")

def die(msg: str):
    print(f"\n  \033[31m[x] {msg}\033[0m", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="benibust",
        description="BeniBust — owner root for Beni/Mondo X5 (right-to-repair jailbreak).",
        epilog="Owner-initiated; use only on hardware you own. See BENIBUST.md.",
    )
    p.add_argument("--host", metavar="IP",
                   help="Robot IP (default: auto-discover)")
    p.add_argument("--base", metavar="PATH",
                   help="V26.11 all_in_one.zip (default: auto-discover)")
    p.add_argument("--hbre", metavar="PATH",
                   help="Stock hbre.img, 157,286,400 B (default: auto-discover; dump your own with "
                        "`python3 -m freewheel.ota dump-partition hbre --host IP`)")
    p.add_argument("--version", default=None,
                   help="Package version string (default: auto-bump)")
    p.add_argument("--output", metavar="PATH", default=None,
                   help="Output package path (default: auto-named in beni_fw/)")
    p.add_argument("--dry-run", action="store_true",
                   help="Build the package but don't upload or flash")
    p.add_argument("--skip-build", metavar="PKG",
                   help="Skip build, flash this pre-built package")
    p.add_argument("--force", action="store_true",
                   help="Skip confirmation prompts")
    p.add_argument("--payload", choices=("both", "ssh", "telnet"), default="both",
                   help="root channel payload (default: both = key-only SSH + AP-only telnet)")
    p.add_argument("--ssh-key", default=str(DEFAULT_SSH_KEY),
                   help="local private key (created if missing)")
    p.add_argument("--ssh-port", type=int, default=2222,
                   help="remote SSH port (default 2222)")
    p.add_argument("--i-own-this-device", action="store_true",
                   help="attest ownership (required unless interactive or --force)")
    p.add_argument("--backup-dir", metavar="DIR", default=None,
                   help="after root, save a device state snapshot here")
    p.add_argument("--restore", metavar="PKG", default=None,
                   help="flash a stock vendor package (rollback) instead of building BeniBust")
    p.add_argument("--scan", action="store_true",
                   help="read-only device scan and exit")
    p.add_argument("--fetch-firmware", action="store_true",
                   help="pull all_in_one.zip + hbre.img off your robot's :8085 and exit")
    p.add_argument("--firmware-dir", metavar="DIR", default="beni_fw",
                   help="where --fetch-firmware writes (default: beni_fw)")
    p.add_argument("--shell", action="store_true",
                   help="connect to an existing root channel and exit")
    return p.parse_args()


CONSENT = """\
BeniBust is an owner-initiated right-to-repair tool. Use it only on devices you
own. It writes the inactive A/B slot through the device's OTA interface; keep a
vendor full package for restore. Do not use it remotely or on third-party
hardware. Keep vendor communication open for responsible disclosure.
"""


def _consent(args) -> bool:
    print(CONSENT)
    if args.i_own_this_device or args.force:
        return True
    try:
        ans = input("Type 'yes' to confirm you own this device and accept the risks: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans == "yes"


def main() -> int:
    args = parse_args()

    print("\033[1;37m")
    print("  ╔══════════════════════════════════════════╗")
    print("  ║             B E N I B U S T              ║")
    print("  ║   owner root for Beni/Mondo X5 (LZ110)   ║")
    print("  ║  right-to-repair jailbreak — own device  ║")
    print("  ╚══════════════════════════════════════════╝")
    print("\033[0m")

    if args.scan:
        return scan_robot(discover_robot(args.host))
    if args.fetch_firmware:
        return fetch_firmware(args.host, args.firmware_dir)
    if args.shell:
        return connect_shell(discover_robot(args.host), Path(args.ssh_key), args.ssh_port)

    if not (1 <= args.ssh_port <= 65535):
        die("--ssh-port must be 1..65535")

    if not _consent(args):
        info("Aborted (ownership not confirmed).")
        return 1

    ssh_key = Path(args.ssh_key)
    ssh_pubkey = ensure_ssh_key(ssh_key) if args.payload in ("ssh", "both") else ""

    # --- Discover inputs ---
    base_zip: Path | None = None
    if args.restore:
        pkg_path = Path(args.restore)
        if not pkg_path.is_file():
            die(f"Restore package not found: {pkg_path}")
        ok(f"Restore package: {pkg_path.name}")
    elif args.skip_build:
        pkg_path = Path(args.skip_build)
        if not pkg_path.is_file():
            die(f"Package not found: {pkg_path}")
        ok(f"Using pre-built package: {pkg_path.name}")
    else:
        base_zip = find_base_zip(args.base)
        ok(f"Base firmware: {base_zip}")

        hbre_img = find_hbre_img(args.hbre)
        ok(f"Stock hbre.img: {hbre_img} ({hbre_img.stat().st_size / 1e6:.0f} MB)")

        version = args.version or f"26.11.19.{int(time.time()) % 100:02d}"
        output = Path(args.output) if args.output else Path(f"beni_fw/build_26.11/V{version}_lz110_benibust.zip")
        output.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="freewheel_") as tmp:
            pkg_path = build_package(
                base_zip, hbre_img, output, version, Path(tmp),
                payload=args.payload, ssh_pubkey=ssh_pubkey, ssh_port=args.ssh_port,
            )

        print(f"\n  Package ready: {pkg_path} ({pkg_path.stat().st_size / 1e6:.1f} MB)")

    if args.dry_run:
        ok("Dry run — stopping before upload.")
        return 0

    # --- Discover robot ---
    host = discover_robot(args.host)
    ok(f"Robot found at {host}")

    # --- Confirm ---
    if not args.force:
        print(f"\n  About to flash {pkg_path.name} to {host}.")
        print("  The robot will reboot. Close the Mondo app first (UCP is single-session).")
        try:
            ans = input("\n  Proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        if ans not in ("y", "yes"):
            info("Aborted.")
            return 0

    # --- Upload ---
    upload_result = upload_package(pkg_path, host, base_zip)

    # --- Install ---
    install_ota(
        host,
        upgrade_id=upload_result["upgrade_id"],
        upload_token=upload_result["upload_token"],
    )

    # --- Monitor ---
    monitor_ota(host, timeout_sec=300)

    if args.restore:
        warn("Restore note: a stock V26.11 package has no hbre, so it won't undo BeniBust.")
        warn("Keep your own pristine dump (`python -m freewheel.ota dump-partition hbre --slot a|b`)")
        warn("or a vendor full package that includes hbre, then verify the intended slot boots.")
        return 0

    # --- Wait for reboot and verify ---
    info("Waiting 30s for reboot...")
    time.sleep(30)

    if not verify_root(host, args.ssh_port, ssh_key):
        info("Try reconnecting to the robot AP (Beni-xxxxxx) and running:")
        info(f"  python3 benibust.py --host {ROBOT_AP_IP} --scan")
        info(f"  python3 benibust.py --host {ROBOT_AP_IP} --shell")
        return 1

    if args.backup_dir:
        backup_state(host, ssh_key, args.ssh_port, args.backup_dir)

    ok("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
