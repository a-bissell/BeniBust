"""Pre-flash partition backups (mondo + misc boot state) and rollback restore.

Uses the same SSH `dd` path as `dump_partition`, with a human-readable manifest next
to the image files. Flashing refuses to proceed without a verified backup when root
SSH is reachable, unless the caller sets an explicit override.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .ota import (
    HBRE_PARTITION_BYTES,
    KNOWN_PARTITION_BYTES,
    _BY_NAME_DIR,
    _ssh_argv,
    dump_partition,
    sha256_file,
)

ROLLBACK_MANIFEST = "rollback-manifest.txt"
DEFAULT_BACKUP_ROOT = Path("beni_fw/rollback")

# Required before any destructive write when root SSH is up.
REQUIRED_BACKUPS: Tuple[Tuple[str, str], ...] = (("mondo", "current"), ("misc", "current"))
# Written when reachable so --restore can put both slots back.
OPTIONAL_SLOT_BACKUPS: Tuple[Tuple[str, str], ...] = (
    ("mondo", "a"),
    ("mondo", "b"),
    ("hbre", "a"),
    ("hbre", "b"),
)

DOCTOR_PARTITIONS: Tuple[Tuple[str, str], ...] = REQUIRED_BACKUPS + OPTIONAL_SLOT_BACKUPS

SLOT_SUFFIX_RE = re.compile(r"hobotboot\.slot_suffix=(\S+)")


class PartitionBackupError(Exception):
    """Backup or restore failed."""


class BackupRefusalError(PartitionBackupError):
    """Flash refused because rollback material is missing or unverified."""


@dataclass
class RobotBootProbe:
    firmware_version: str = ""
    cmdline: str = ""
    active_slot: str = ""
    misc_hex_preview: str = ""

    def as_manifest_header(self) -> Dict[str, str]:
        return {
            "firmware_version": self.firmware_version,
            "cmdline": self.cmdline,
            "active_slot": self.active_slot,
            "misc_boot_state_hex": self.misc_hex_preview,
        }


@dataclass
class BackupImageEntry:
    partition: str
    slot: str
    filename: str
    bytes: int
    sha256: str
    captured_at: str = ""
    node: str = ""
    notes: List[str] = field(default_factory=list)

    def image_path(self, backup_dir: Path) -> Path:
        return backup_dir / self.filename


@dataclass
class RollbackManifest:
    created: str
    probe: RobotBootProbe
    images: List[BackupImageEntry] = field(default_factory=list)

    def find(self, partition: str, slot: str) -> Optional[BackupImageEntry]:
        for img in self.images:
            if img.partition == partition and img.slot == slot:
                return img
        return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def probe_robot_boot_state(
    host: str,
    *,
    ssh_port: int = 2222,
    ssh_key: Optional[str] = None,
    timeout: float = 20.0,
) -> RobotBootProbe:
    """Read /etc/version, /proc/cmdline, and a short misc preview over SSH."""
    ssh = _ssh_argv(host, port=ssh_port, key=ssh_key)
    script = (
        "echo '---VERSION---'; cat /etc/version 2>/dev/null; "
        "echo '---CMDLINE---'; cat /proc/cmdline 2>/dev/null; "
        "echo '---MISC---'; "
        f"dd if={_BY_NAME_DIR}/misc bs=256 count=4 2>/dev/null | hexdump -C | head -n 8"
    )
    res = subprocess.run(ssh + [script], capture_output=True, text=True, timeout=timeout)
    if res.returncode != 0:
        raise PartitionBackupError(
            f"cannot probe robot boot state over SSH: {(res.stderr or res.stdout).strip()}"
        )
    text = res.stdout
    version = ""
    cmdline = ""
    misc = ""
    section = None
    for line in text.splitlines():
        if line.strip() == "---VERSION---":
            section = "version"
            continue
        if line.strip() == "---CMDLINE---":
            section = "cmdline"
            continue
        if line.strip() == "---MISC---":
            section = "misc"
            continue
        if section == "version" and line.strip():
            version = line.strip()
        elif section == "cmdline":
            cmdline = (cmdline + " " + line).strip() if cmdline else line.strip()
        elif section == "misc":
            misc = (misc + "\n" + line).strip() if misc else line.strip()

    active = ""
    m = SLOT_SUFFIX_RE.search(cmdline)
    if m:
        active = m.group(1)

    return RobotBootProbe(
        firmware_version=version,
        cmdline=cmdline,
        active_slot=active,
        misc_hex_preview=misc,
    )


def _image_filename(partition: str, slot: str) -> str:
    if slot == "current":
        return f"{partition}_active.img"
    return f"{partition}_{slot}.img"


def write_manifest_human(backup_dir: Path, manifest: RollbackManifest) -> Path:
    """Write a human-readable manifest; also drop a JSON sidecar for tests."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    path = backup_dir / ROLLBACK_MANIFEST
    lines: List[str] = [
        "# BeniBust rollback manifest — partition images for mondo + slot/misc restore",
        f"created: {manifest.created}",
        f"firmware_version: {manifest.probe.firmware_version}",
        f"active_slot: {manifest.probe.active_slot}",
        f"cmdline: {manifest.probe.cmdline}",
        "",
        "misc_boot_state (first 1 KiB of /misc, hexdump):",
        manifest.probe.misc_hex_preview or "(unavailable)",
        "",
    ]
    for img in manifest.images:
        lines += [
            f"[{img.partition} slot={img.slot}]",
            f"  file: {img.filename}",
            f"  bytes: {img.bytes:,}",
            f"  sha256: {img.sha256}",
            f"  captured: {img.captured_at or manifest.created}",
            f"  node: {img.node or '(unknown)'}",
        ]
        for note in img.notes:
            lines.append(f"  note: {note}")
        lines.append("")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    (backup_dir / "rollback-manifest.json").write_text(
        json.dumps(
            {
                "created": manifest.created,
                "probe": asdict(manifest.probe),
                "images": [asdict(i) for i in manifest.images],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


def load_manifest(backup_dir: Path) -> Optional[RollbackManifest]:
    json_path = backup_dir / "rollback-manifest.json"
    if json_path.is_file():
        data = json.loads(json_path.read_text(encoding="utf-8"))
        probe = RobotBootProbe(**data.get("probe", {}))
        images = [BackupImageEntry(**entry) for entry in data.get("images", [])]
        return RollbackManifest(created=data.get("created", ""), probe=probe, images=images)

    text_path = backup_dir / ROLLBACK_MANIFEST
    if not text_path.is_file():
        return None

    probe = RobotBootProbe()
    images: List[BackupImageEntry] = []
    created = ""
    current: Optional[BackupImageEntry] = None
    in_misc = False
    misc_lines: List[str] = []
    for raw in text_path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if line.startswith("created:"):
            created = line.split(":", 1)[1].strip()
        elif line.startswith("firmware_version:"):
            probe.firmware_version = line.split(":", 1)[1].strip()
        elif line.startswith("active_slot:"):
            probe.active_slot = line.split(":", 1)[1].strip()
        elif line.startswith("cmdline:"):
            probe.cmdline = line.split(":", 1)[1].strip()
        elif line.startswith("misc_boot_state"):
            in_misc = True
            continue
        elif in_misc:
            if line.startswith("[") and "slot=" in line:
                in_misc = False
                probe.misc_hex_preview = "\n".join(misc_lines).strip()
                misc_lines = []
            elif line.strip():
                misc_lines.append(line)
        if line.startswith("[") and "slot=" in line:
            if current is not None:
                images.append(current)
            m = re.match(r"\[(?P<part>\w+) slot=(?P<slot>[^\]]+)\]", line)
            if not m:
                continue
            current = BackupImageEntry(
                partition=m.group("part"),
                slot=m.group("slot"),
                filename="",
                bytes=0,
                sha256="",
            )
        elif current is not None and line.strip().startswith("file:"):
            current.filename = line.split(":", 1)[1].strip()
        elif current is not None and line.strip().startswith("bytes:"):
            current.bytes = int(line.split(":", 1)[1].strip().replace(",", ""))
        elif current is not None and line.strip().startswith("sha256:"):
            current.sha256 = line.split(":", 1)[1].strip()
        elif current is not None and line.strip().startswith("node:"):
            current.node = line.split(":", 1)[1].strip()
    if current is not None:
        images.append(current)
    if in_misc and misc_lines:
        probe.misc_hex_preview = "\n".join(misc_lines).strip()
    if not created and not images:
        return None
    return RollbackManifest(created=created or _utc_now(), probe=probe, images=images)


def _verify_image_on_disk(entry: BackupImageEntry, backup_dir: Path) -> Tuple[bool, str]:
    path = entry.image_path(backup_dir)
    if not path.is_file():
        return False, f"missing image {entry.filename}"
    size = path.stat().st_size
    if entry.bytes and size != entry.bytes:
        return False, f"{entry.filename} is {size:,} B, manifest says {entry.bytes:,} B"
    digest = sha256_file(path)
    if entry.sha256 and digest.lower() != entry.sha256.lower():
        return False, f"{entry.filename} sha256 mismatch (disk {digest}, manifest {entry.sha256})"
    return True, digest


def manifest_has_verified_required(backup_dir: Path, probe: RobotBootProbe) -> Tuple[bool, List[str]]:
    """True when required partition images exist, hash-match, and match this firmware build."""
    manifest = load_manifest(backup_dir)
    if manifest is None:
        return False, ["no rollback-manifest.txt in backup directory"]
    reasons: List[str] = []
    if probe.firmware_version and manifest.probe.firmware_version:
        if probe.firmware_version != manifest.probe.firmware_version:
            reasons.append(
                f"manifest firmware {manifest.probe.firmware_version!r} "
                f"!= robot {probe.firmware_version!r}"
            )
    for part, slot in REQUIRED_BACKUPS:
        entry = manifest.find(part, slot)
        if entry is None:
            reasons.append(f"no manifest entry for {part} slot={slot}")
            continue
        ok, detail = _verify_image_on_disk(entry, backup_dir)
        if not ok:
            reasons.append(detail)
    return (len(reasons) == 0, reasons)


def ensure_pre_flash_backups(
    host: str,
    backup_dir: Path,
    *,
    ssh_port: int = 2222,
    ssh_key: Optional[str] = None,
    allow_without: bool = False,
    include_optional_slots: bool = True,
    progress: Optional[Callable[[str, int, int], None]] = None,
    log: Optional[Callable[[str], None]] = None,
) -> RollbackManifest:
    """Capture or reuse verified mondo + misc backups before flashing."""
    backup_dir = Path(backup_dir)
    try:
        probe = probe_robot_boot_state(host, ssh_port=ssh_port, ssh_key=ssh_key)
    except PartitionBackupError as exc:
        if allow_without:
            log and log(f"backup skipped (probe failed, override set): {exc}")
            return RollbackManifest(created=_utc_now(), probe=RobotBootProbe())
        raise BackupRefusalError(
            "refusing flash: cannot reach root SSH to capture or verify a mondo/misc "
            f"backup before writing the inactive slot.\n"
            f"  {exc}\n"
            "  Pass --allow-flash-without-backup only if you have another rollback path "
            "(untouched slot B, U-Boot, or a vendor full package)."
        ) from exc

    ok, reasons = manifest_has_verified_required(backup_dir, probe)
    if ok:
        manifest = load_manifest(backup_dir)
        assert manifest is not None
        log and log(
            f"reusing verified rollback backup in {backup_dir} "
            f"(firmware {manifest.probe.firmware_version!r}, "
            f"{len(manifest.images)} image(s))"
        )
        return manifest

    if allow_without:
        log and log("flash override: proceeding without a verified mondo/misc backup")
        return RollbackManifest(created=_utc_now(), probe=probe)

    if reasons:
        log and log(
            "existing rollback backup is missing or stale — capturing fresh images:\n"
            + "\n".join(f"    - {r}" for r in reasons)
        )

    log and log(f"capturing rollback images to {backup_dir} (robot {probe.firmware_version!r})")
    targets: List[Tuple[str, str]] = list(REQUIRED_BACKUPS)
    if include_optional_slots:
        targets += list(OPTIONAL_SLOT_BACKUPS)

    images: List[BackupImageEntry] = []
    for part, slot in targets:
        dest = backup_dir / _image_filename(part, slot)
        expected = KNOWN_PARTITION_BYTES.get(part)
        if part == "hbre" and expected is None:
            expected = HBRE_PARTITION_BYTES

        def _prog(done: int, total: int, label: str = part) -> None:
            if progress is not None:
                progress(f"{label}:{slot}", done, total)

        try:
            res = dump_partition(
                part,
                host=host,
                ssh_port=ssh_port,
                ssh_key=ssh_key,
                slot=slot,
                out=dest,
                expected_size=expected,
                progress=lambda d, t: _prog(d, t),
            )
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
            if (part, slot) in REQUIRED_BACKUPS:
                raise BackupRefusalError(
                    f"refusing flash: failed to dump required partition {part} (slot {slot}): {exc}"
                ) from exc
            log and log(f"optional backup skipped for {part} slot={slot}: {exc}")
            continue

        if not res.get("ok"):
            if (part, slot) in REQUIRED_BACKUPS:
                notes = "; ".join(res.get("notes") or [])
                raise BackupRefusalError(
                    f"refusing flash: {part} slot={slot} dump rejected: {notes}"
                )
            continue

        images.append(
            BackupImageEntry(
                partition=part,
                slot=slot,
                filename=dest.name,
                bytes=int(res["bytes"]),
                sha256=str(res["sha256"]),
                captured_at=_utc_now(),
                node=str(res.get("node", "")),
            )
        )

    manifest = RollbackManifest(created=_utc_now(), probe=probe, images=images)
    write_manifest_human(backup_dir, manifest)
    ok2, reasons2 = manifest_has_verified_required(backup_dir, probe)
    if not ok2:
        raise BackupRefusalError(
            "refusing flash: backup capture finished but verification failed:\n"
            + "\n".join(f"    - {r}" for r in reasons2)
        )
    return manifest


def restore_partition_image(
    partition: str,
    local_image: Path,
    *,
    host: str,
    expected_sha256: str,
    ssh_port: int = 2222,
    ssh_key: Optional[str] = None,
    slot: str = "current",
    progress: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Any]:
    """Write a local image back to the robot with hash verification first."""
    local_image = Path(local_image)
    if not local_image.is_file():
        raise PartitionBackupError(f"restore image not found: {local_image}")
    digest = sha256_file(local_image)
    want = expected_sha256.lower()
    if digest.lower() != want:
        raise PartitionBackupError(
            f"refusing restore: {local_image.name} sha256 is {digest}, manifest expects {want}"
        )

    if slot not in ("current", "a", "b"):
        raise ValueError(f"slot must be current|a|b, not {slot!r}")
    node = f"{_BY_NAME_DIR}/{partition}" if slot == "current" else f"{_BY_NAME_DIR}/{partition}_{slot}"
    size = local_image.stat().st_size
    ssh = _ssh_argv(host, port=ssh_port, key=ssh_key)

    probe = subprocess.run(
        ssh + [f"readlink -f {node}; blockdev --getsize64 {node} 2>/dev/null || "
               f"stat -c %s {node}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if probe.returncode != 0:
        raise PartitionBackupError(
            f"cannot open {node} for restore: {(probe.stderr or probe.stdout).strip()}"
        )

    payload = local_image.read_bytes()
    proc = subprocess.Popen(
        ssh + [f"dd of={node} bs=1M conv=fsync 2>/dev/null"],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _out, err = proc.communicate(input=payload)
    sent = len(payload)
    if progress is not None:
        progress(sent, size)
    if proc.returncode != 0:
        raise PartitionBackupError(
            f"dd restore to {node} failed: {err.decode('utf-8', 'replace').strip()}"
        )
    if sent != size:
        raise PartitionBackupError(f"restore sent {sent:,} bytes, expected {size:,}")

    return {
        "partition": partition,
        "slot": slot,
        "node": node,
        "local": str(local_image),
        "bytes": sent,
        "sha256": digest,
    }


def plan_restore(manifest: RollbackManifest, backup_dir: Path) -> List[Tuple[BackupImageEntry, str]]:
    """Return (entry, target_slot) pairs in restore order (misc last before reboot)."""
    order: List[Tuple[str, str]] = []
    for slot in ("a", "b"):
        if manifest.find("mondo", slot):
            order.append(("mondo", slot))
    if manifest.find("mondo", "current"):
        order.append(("mondo", "current"))
    if manifest.find("hbre", "a"):
        order.append(("hbre", "a"))
    if manifest.find("hbre", "b"):
        order.append(("hbre", "b"))
    if manifest.find("misc", "current"):
        order.append(("misc", "current"))

    planned: List[Tuple[BackupImageEntry, str]] = []
    for part, slot in order:
        entry = manifest.find(part, slot)
        if entry is None:
            continue
        ok, detail = _verify_image_on_disk(entry, backup_dir)
        if not ok:
            raise PartitionBackupError(detail)
        planned.append((entry, slot))
    return planned


def describe_restore_plan(
    manifest: RollbackManifest,
    backup_dir: Path,
) -> str:
    planned = plan_restore(manifest, backup_dir)
    active = manifest.probe.active_slot or "(unknown)"
    lines = [
        "Rollback restore plan:",
        f"  firmware version (at backup): {manifest.probe.firmware_version!r}",
        f"  active slot at backup time: {active}",
        f"  after restore the bootloader still boots the slot in misc/cmdline — verify with /proc/cmdline.",
        "  partitions to write:",
    ]
    for entry, slot in planned:
        lines.append(
            f"    - {entry.partition} slot={slot} -> {entry.filename} "
            f"({entry.bytes:,} B, sha256 {entry.sha256[:16]}…)"
        )
    if not planned:
        lines.append("    (none — manifest has no restorable images)")
    return "\n".join(lines)


def execute_restore(
    host: str,
    backup_dir: Path,
    *,
    ssh_port: int = 2222,
    ssh_key: Optional[str] = None,
    progress: Optional[Callable[[str, int, int], None]] = None,
) -> List[Dict[str, Any]]:
    backup_dir = Path(backup_dir)
    manifest = load_manifest(backup_dir)
    if manifest is None:
        raise PartitionBackupError(f"no {ROLLBACK_MANIFEST} in {backup_dir}")

    results: List[Dict[str, Any]] = []
    for entry, slot in plan_restore(manifest, backup_dir):
        path = entry.image_path(backup_dir)

        def _prog(done: int, total: int) -> None:
            if progress is not None:
                progress(f"{entry.partition}:{slot}", done, total)

        results.append(
            restore_partition_image(
                entry.partition,
                path,
                host=host,
                expected_sha256=entry.sha256,
                ssh_port=ssh_port,
                ssh_key=ssh_key,
                slot=slot,
                progress=_prog,
            )
        )
    return results


def doctor_backup_rows(backup_dir: Path) -> List[Tuple[str, bool, str]]:
    """Rows for freewheel doctor: partition, verified?, detail with age and version."""
    backup_dir = Path(backup_dir)
    manifest = load_manifest(backup_dir)
    version = manifest.probe.firmware_version if manifest else ""
    created = manifest.created if manifest else ""
    age = ""
    if created:
        try:
            ts = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            mins = int((datetime.now(timezone.utc) - ts).total_seconds() // 60)
            age = f"{mins} min ago" if mins < 120 else f"{mins // 60} h ago"
        except ValueError:
            age = created

    rows: List[Tuple[str, bool, str]] = []
    for part, slot in DOCTOR_PARTITIONS:
        label = f"backup {part} ({slot})"
        if manifest is None:
            rows.append((label, False, f"no manifest under {backup_dir}"))
            continue
        entry = manifest.find(part, slot)
        if entry is None:
            req = (part, slot) in REQUIRED_BACKUPS
            rows.append(
                (
                    label,
                    not req,
                    "missing from manifest" + (" — required before flash" if req else " (optional)"),
                )
            )
            continue
        ok, detail = _verify_image_on_disk(entry, backup_dir)
        ver = f"fw {version!r}" if version else "fw unknown"
        extra = f", {age}" if age else ""
        rows.append(
            (
                label,
                ok,
                f"verified {entry.filename}, {entry.bytes:,} B, {ver}{extra}" if ok else detail,
            )
        )
    return rows