"""Unprivileged `ext4` image inspection and patching via `e2fsprogs`.

Used by `benibust.py` and `freewheel.ota` to extract binaries from
`hbre.img` (e.g. OpenSSH `sshd` from V26.09) and apply file overlays/deletes
onto `system.img` / `mondo.img` without root privileges or loop mounts.

Requires `e2fsprogs` (`debugfs`, `dumpe2fs`, `e2fsck`) on macOS (`brew install e2fsprogs`)
or Linux (`apt install e2fsprogs`). Zero third-party Python dependencies.
"""
from __future__ import annotations

import hashlib
import os
import posixpath
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Dict, Iterable, List, Optional

_E2FS_SEARCH_DIRS = (
    "/opt/homebrew/opt/e2fsprogs/sbin",
    "/opt/homebrew/opt/e2fsprogs/bin",
    "/usr/local/opt/e2fsprogs/sbin",
    "/usr/local/opt/e2fsprogs/bin",
    "/usr/sbin",
    "/sbin",
)

_MIN_FREE_INODES = 32

MOND_VERITY_CONF_PATHS = (
    "/etc/lz100-mondo-verity.conf",
    "/etc/lz100-mondo-avb",
)
_STAT_INODE_RE = re.compile(
    r"Inode:\s*(?P<inode>\d+)\s+Type:\s*(?P<type>\S+)\s+Mode:\s*(?P<mode>[0-7]+)"
)
_STAT_SIZE_RE = re.compile(r"Size:\s*(?P<size>\d+)")

# Raw superblock layout (ext4, offset 1024 into the image).
EXT4_SUPERBLOCK_OFFSET = 1024
EXT4_SUPERBLOCK_SIZE = 1024
EXT4_MAGIC = 0xEF53

# RO_COMPAT 0x4000 == `shared_blocks`: a deduplicated, read-only filesystem.
# The Linux ext4 driver refuses to mount one read-write
# (`EXT4-fs: couldn't mount RDWR because of unsupported optional features (4000)`),
# and `e2fsck -fn` on such an image exits 0, so nothing else in this module notices.
RO_COMPAT_SHARED_BLOCKS = 0x4000
COMPAT_HAS_JOURNAL = 0x0004


class Ext4UnsafeImageError(ValueError):
    """Raised when an image cannot be edited or safely mounted read-write as-is."""


@dataclass(frozen=True)
class Ext4Features:
    """The three superblock feature words, plus the checks that matter to us."""

    compat: int = 0
    incompat: int = 0
    ro_compat: int = 0
    is_ext4: bool = False

    @property
    def shared_blocks(self) -> bool:
        return bool(self.ro_compat & RO_COMPAT_SHARED_BLOCKS)

    @property
    def has_journal(self) -> bool:
        return bool(self.compat & COMPAT_HAS_JOURNAL)

    def names(self) -> List[str]:
        out: List[str] = []
        if self.has_journal:
            out.append("has_journal")
        if self.shared_blocks:
            out.append("shared_blocks")
        return out

    def read_write_blockers(self) -> List[str]:
        """Reasons a `mount -o rw` would be refused on this filesystem."""
        problems: List[str] = []
        if self.shared_blocks:
            problems.append(
                "shared_blocks (RO_COMPAT 0x4000): deduplicated read-only ext4 — "
                "the kernel refuses a read-write mount"
            )
        return problems


def read_superblock(source: str | Path | BinaryIO, *, read: int = EXT4_SUPERBLOCK_SIZE) -> Ext4Features:
    """Read ext4 feature words straight from the superblock.

    `source` is a path or any binary file object (a `ZipExtFile` works), so callers can
    inspect an image inside an OTA package without extracting a 1 GB file. Only ~2 KiB
    are read. A non-ext4 blob returns `Ext4Features(is_ext4=False)` rather than raising,
    because packages legitimately carry non-ext4 payloads.
    """
    blob = b""
    if hasattr(source, "read"):
        fp, should_close = source, False
    else:
        fp, should_close = open(source, "rb"), True
    try:
        try:
            fp.seek(EXT4_SUPERBLOCK_OFFSET)
        except (OSError, ValueError):
            return Ext4Features()
        blob = fp.read(read)
    finally:
        if should_close:
            fp.close()
    if len(blob) < 0x68:
        return Ext4Features()
    magic = struct.unpack_from("<H", blob, 0x38)[0]
    if magic != EXT4_MAGIC:
        return Ext4Features()
    compat = struct.unpack_from("<I", blob, 0x5C)[0]
    incompat = struct.unpack_from("<I", blob, 0x60)[0]
    ro_compat = struct.unpack_from("<I", blob, 0x64)[0]
    return Ext4Features(compat=compat, incompat=incompat, ro_compat=ro_compat, is_ext4=True)


@dataclass(frozen=True)
class Ext4Stats:
    block_size: int
    block_count: int
    free_blocks: int
    inode_count: int
    free_inodes: int

    @property
    def total_bytes(self) -> int:
        return self.block_count * self.block_size

    @property
    def free_bytes(self) -> int:
        return self.free_blocks * self.block_size


@dataclass(frozen=True)
class Ext4InodeStat:
    inode: int
    file_type: str
    mode: int
    size: int


@dataclass(frozen=True)
class _OverlayWritePlan:
    local_file: Path
    remote_file: str
    perm: int
    sha256: str
    size: int
    existed: bool


def find_e2fs_tool(name: str) -> str:
    """Locate an `e2fsprogs` tool (`debugfs`, `dumpe2fs`, `e2fsck`) across PATH + sbin."""
    env_override = os.environ.get(f"FREEWHEEL_{name.upper()}")
    if env_override and os.access(env_override, os.X_OK):
        return env_override

    extra = os.pathsep.join(d for d in _E2FS_SEARCH_DIRS if os.path.isdir(d))
    cur_path = os.environ.get("PATH", "")
    search_path = f"{cur_path}{os.pathsep}{extra}" if extra else cur_path
    found = shutil.which(name, path=search_path)
    if not found:
        raise FileNotFoundError(
            f"Required e2fsprogs binary {name!r} was not found. "
            "Install e2fsprogs (`brew install e2fsprogs` on macOS, `sudo apt install e2fsprogs` on Linux)."
        )
    return found


def _quote_debugfs(arg: str) -> str:
    if any(c in arg for c in ('"', "\n", "\r", "\x00")):
        raise ValueError(f"Unsafe path character for debugfs: {arg!r}")
    return f'"{arg}"'


def _debugfs_errors(stderr: str) -> List[str]:
    out: List[str] = []
    for raw in stderr.splitlines():
        line = raw.strip()
        if not line or line.startswith("debugfs "):
            continue
        out.append(line)
    return out


def _round_blocks(num_bytes: int, block_size: int) -> int:
    if num_bytes <= 0:
        return 0
    return ((num_bytes + block_size - 1) // block_size) * block_size


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def _infer_file_perm(local_file: Path, remote_file: str, overrides: Dict[str, int]) -> int:
    if remote_file in overrides:
        return overrides[remote_file] & 0o7777
    host_mode = local_file.stat().st_mode & 0o7777
    if host_mode & 0o111:
        return host_mode
    with local_file.open("rb") as fp:
        hdr = fp.read(4)
    if hdr == b"\x7fELF" or hdr.startswith(b"#!"):
        return 0o755
    if remote_file.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")) or remote_file.endswith(".sh"):
        return 0o755
    return host_mode if host_mode else 0o644


class Ext4Image:
    """Wrapper around `debugfs` / `dumpe2fs` / `e2fsck` for offline `ext4` image operations."""

    def __init__(self, image_path: str | Path) -> None:
        self.path = Path(image_path).resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"ext4 image not found: {self.path}")
        self._debugfs = find_e2fs_tool("debugfs")
        self._dumpe2fs = find_e2fs_tool("dumpe2fs")
        self._e2fsck = find_e2fs_tool("e2fsck")

    def features(self) -> Ext4Features:
        """Superblock feature words, read directly (works without `dumpe2fs`)."""
        return read_superblock(self.path)

    def mondo_dm_verity_reasons(self, *, vbmeta_blob: Optional[bytes] = None) -> List[str]:
        """Non-shared_blocks dm-verity signals inside this image (config files, vbmeta)."""
        from . import avb

        reasons: List[str] = []
        for conf in MOND_VERITY_CONF_PATHS:
            if self.path_exists(conf):
                reasons.append(f"contains {conf}")
        if vbmeta_blob:
            vb = avb.parse_vbmeta(vbmeta_blob)
            if vb.mondo_hashtree:
                reasons.append("vbmeta AvbHashtreeDescriptor names mondo")
            if vb.mondo_hash:
                reasons.append("vbmeta AvbHashDescriptor names mondo")
        return reasons

    def assert_mondo_patchable(self, *, vbmeta_blob: Optional[bytes] = None,
                               allow_verity_patch: bool = False) -> None:
        """Refuse in-place `mondo.img` edits when dm-verity metadata says the slot is verified.

        Distinct from `assert_editable()` (shared_blocks). Only `--allow-verity-patch` bypasses this.
        """
        reasons = self.mondo_dm_verity_reasons(vbmeta_blob=vbmeta_blob)
        if not reasons:
            return
        if allow_verity_patch:
            return
        raise Ext4UnsafeImageError(
            f"refusing to modify {self.path.name}: dm-verity protected ({'; '.join(reasons)}). "
            "In-place edits change image bytes so the hash tree no longer matches the root hash in vbmeta; "
            "the kernel reports dm-verity-corrupted, refuses to mount /md, and the bootloader may roll "
            "the slot back. Pass allow_verity_patch=True only when rebuilding vbmeta and accepting brick risk."
        )

    def assert_editable(self) -> Ext4Features:
        """Refuse to edit a filesystem that cannot be mounted read-write.

        A `shared_blocks` image only ever mounts `ro,noload` behind dm-verity. Editing it
        in place is doubly wrong: the write is meaningless if the slot is verified, and
        the resulting slot cannot be mounted read-write by a `system.img` that still mounts
        `/md` with `defaults`. Both halves of that pairing have bricked a robot, so this
        refuses instead of guessing.
        """
        feats = self.features()
        blockers = feats.read_write_blockers()
        if blockers:
            raise Ext4UnsafeImageError(
                f"refusing to modify {self.path.name}: " + "; ".join(blockers) + ". "
                "Pair it with an updated system.img that mounts /md read-only, or convert it first "
                "(`e2fsck -yf -E unshare_blocks` then `tune2fs -O has_journal`) and verify a "
                "read-write mount on the robot before flashing."
            )
        return feats

    def get_fs_stats(self) -> Ext4Stats:
        res = subprocess.run(
            [self._dumpe2fs, "-h", str(self.path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            raise RuntimeError(f"dumpe2fs -h failed on {self.path.name}:\n{res.stderr.strip()}")
        kv: Dict[str, str] = {}
        for line in res.stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                kv[k.strip()] = v.strip()
        try:
            return Ext4Stats(
                block_size=int(kv["Block size"]),
                block_count=int(kv["Block count"]),
                free_blocks=int(kv["Free blocks"]),
                inode_count=int(kv["Inode count"]),
                free_inodes=int(kv["Free inodes"]),
            )
        except (KeyError, ValueError) as exc:
            raise RuntimeError(f"Unable to parse dumpe2fs superblock fields for {self.path.name}: {exc}") from exc

    def run_debugfs(self, commands: Iterable[str], *, write: bool = False) -> str:
        cmd_list = [c.strip() for c in commands if c.strip()]
        if not cmd_list:
            return ""
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="fw_debugfs_", suffix=".cmd", delete=False) as tf:
            tf.write("\n".join(cmd_list) + "\n")
            script_path = Path(tf.name)
        try:
            argv = [self._debugfs]
            if write:
                argv.append("-w")
            argv.extend(["-f", str(script_path), str(self.path)])
            res = subprocess.run(argv, capture_output=True, text=True, check=False)
            errs = _debugfs_errors(res.stderr)
            if res.returncode != 0 or errs:
                detail = "\n".join(errs) or res.stderr.strip() or f"exit {res.returncode}"
                raise RuntimeError(f"debugfs failed on {self.path.name}:\n{detail}")
            return res.stdout
        finally:
            script_path.unlink(missing_ok=True)

    def stat_path(self, remote_path: str) -> Optional[Ext4InodeStat]:
        norm = "/" + remote_path.lstrip("/")
        res = subprocess.run(
            [self._debugfs, "-R", f"stat {_quote_debugfs(norm)}", str(self.path)],
            capture_output=True,
            text=True,
            check=False,
        )
        errs = _debugfs_errors(res.stderr)
        if res.returncode != 0 or any("File not found" in e for e in errs):
            return None
        if errs:
            raise RuntimeError(f"debugfs stat failed on {norm} ({self.path.name}): {errs}")
        m_ino = _STAT_INODE_RE.search(res.stdout)
        m_sz = _STAT_SIZE_RE.search(res.stdout)
        if not m_ino or not m_sz:
            raise RuntimeError(f"Could not parse debugfs stat output for {norm} in {self.path.name}:\n{res.stdout}")
        return Ext4InodeStat(
            inode=int(m_ino.group("inode")),
            file_type=m_ino.group("type"),
            mode=int(m_ino.group("mode"), 8),
            size=int(m_sz.group("size")),
        )

    def path_exists(self, remote_path: str) -> bool:
        return self.stat_path(remote_path) is not None

    def dump_file_to(self, remote_path: str, dest_path: str | Path) -> None:
        norm = "/" + remote_path.lstrip("/")
        out = Path(dest_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.unlink(missing_ok=True)
        res = subprocess.run(
            [self._debugfs, "-R", f"dump {_quote_debugfs(norm)} {_quote_debugfs(str(out))}", str(self.path)],
            capture_output=True,
            text=True,
            check=False,
        )
        errs = _debugfs_errors(res.stderr)
        if res.returncode != 0 or errs or not out.is_file():
            detail = "\n".join(errs) or res.stderr.strip() or "output file not written"
            raise FileNotFoundError(f"Failed to dump {norm} from {self.path.name}: {detail}")

    def read_file(self, remote_path: str) -> bytes:
        with tempfile.TemporaryDirectory(prefix="fw_ext4_read_") as tmp:
            p = Path(tmp) / "dump.bin"
            self.dump_file_to(remote_path, p)
            return p.read_bytes()

    def read_file_prefix(self, remote_path: str, max_bytes: int = 64) -> bytes:
        with tempfile.TemporaryDirectory(prefix="fw_ext4_hdr_") as tmp:
            p = Path(tmp) / "dump.bin"
            self.dump_file_to(remote_path, p)
            with p.open("rb") as fp:
                return fp.read(max_bytes)

    def list_dir(self, remote_path: str = "/") -> str:
        norm = "/" + remote_path.lstrip("/")
        return self.run_debugfs([f"ls -l {_quote_debugfs(norm)}"], write=False)

    def apply_overlay_and_deletes(
        self,
        overlay_dir: str | Path | None = None,
        delete_paths: Optional[List[str]] = None,
        mode_overrides: Optional[Dict[str, int]] = None,
        *,
        min_free_bytes: Optional[int] = None,
        verify_readback: bool = True,
        allow_verity_patch: bool = False,
        vbmeta_blob: Optional[bytes] = None,
    ) -> Dict[str, int]:
        """Apply file deletions and a directory overlay onto the ext4 image with SHA-256 readback."""
        if self.path.name == "mondo.img":
            self.assert_mondo_patchable(vbmeta_blob=vbmeta_blob, allow_verity_patch=allow_verity_patch)
        self.assert_editable()
        stats = self.get_fs_stats()
        default_reserve = min(32 * 1024 * 1024, int(stats.total_bytes * 0.03))
        reserve_bytes = default_reserve if min_free_bytes is None else max(0, min_free_bytes)
        norm_modes = {("/" + k.lstrip("/")): (v & 0o7777) for k, v in (mode_overrides or {}).items()}

        deleted_targets: List[str] = []
        reclaimed_bytes = 0
        reclaimed_inodes = 0
        for raw_del in delete_paths or []:
            norm = "/" + raw_del.strip().lstrip("/")
            if norm == "/":
                raise ValueError("Refusing to delete '/' from ext4 image")
            st = self.stat_path(norm)
            if st is None:
                continue
            if st.file_type == "directory":
                raise ValueError(f"Refusing to delete directory {norm}; list individual files instead")
            deleted_targets.append(norm)
            reclaimed_bytes += _round_blocks(st.size, stats.block_size)
            reclaimed_inodes += 1

        deleted_set = set(deleted_targets)
        dirs_to_create: List[str] = []
        files_to_write: List[_OverlayWritePlan] = []
        created_dirs = {"/"}
        required_bytes = 0
        required_inodes = 0

        ov_path = Path(overlay_dir) if overlay_dir is not None else None
        if ov_path and ov_path.is_dir():
            for root, dirnames, filenames in os.walk(ov_path):
                dirnames.sort()
                filenames.sort()
                root_p = Path(root)
                rel_dir = root_p.relative_to(ov_path)

                if rel_dir != Path("."):
                    cur = ""
                    for part in rel_dir.parts:
                        cur = posixpath.join(cur, part)
                        rdir = "/" + cur
                        if rdir in created_dirs:
                            continue
                        created_dirs.add(rdir)
                        ex_dir = self.stat_path(rdir)
                        if ex_dir is None:
                            dirs_to_create.append(rdir)
                            required_inodes += 1
                            required_bytes += stats.block_size
                        elif ex_dir.file_type != "directory":
                            raise ValueError(
                                f"Cannot create directory {rdir} in {self.path.name}: "
                                f"{ex_dir.file_type} already exists at that path"
                            )

                for fname in filenames:
                    if fname == ".DS_Store":
                        continue
                    local_file = root_p / fname
                    if local_file.is_symlink():
                        raise ValueError(f"Symlinks in overlay are not supported: {local_file}")
                    rel_file = (rel_dir / fname).as_posix() if rel_dir != Path(".") else fname
                    remote_file = "/" + rel_file.lstrip("/")

                    perm = _infer_file_perm(local_file, remote_file, norm_modes)
                    digest, fsize = _sha256_file(local_file)
                    required_bytes += _round_blocks(fsize, stats.block_size) + stats.block_size + (fsize // 100)
                    required_inodes += 1

                    ex_file = self.stat_path(remote_file)
                    existed = ex_file is not None
                    if ex_file is not None and remote_file not in deleted_set:
                        if ex_file.file_type == "directory":
                            raise ValueError(f"Cannot overwrite directory {remote_file} with a regular file")
                        reclaimed_bytes += _round_blocks(ex_file.size, stats.block_size)
                        reclaimed_inodes += 1

                    files_to_write.append(
                        _OverlayWritePlan(
                            local_file=local_file,
                            remote_file=remote_file,
                            perm=perm,
                            sha256=digest,
                            size=fsize,
                            existed=existed,
                        )
                    )

        net_bytes = max(0, required_bytes - reclaimed_bytes)
        net_inodes = max(0, required_inodes - reclaimed_inodes)
        if stats.free_bytes - net_bytes < reserve_bytes:
            raise RuntimeError(
                f"Insufficient free space in {self.path.name}: need ~{net_bytes} net bytes + "
                f"{reserve_bytes} reserve, only {stats.free_bytes} bytes free."
            )
        if stats.free_inodes - net_inodes < _MIN_FREE_INODES:
            raise RuntimeError(
                f"Insufficient free inodes in {self.path.name}: need {net_inodes}, have {stats.free_inodes}."
            )

        cmds: List[str] = [f"rm {_quote_debugfs(p)}" for p in deleted_targets]
        for d in dirs_to_create:
            qd = _quote_debugfs(d)
            cmds.extend(
                [
                    f"mkdir {qd}",
                    f"set_inode_field {qd} mode 0{0o040755:o}",
                    f"set_inode_field {qd} uid 0",
                    f"set_inode_field {qd} gid 0",
                ]
            )
        for item in files_to_write:
            qr = _quote_debugfs(item.remote_file)
            ql = _quote_debugfs(str(item.local_file.resolve()))
            ext4_mode = 0o100000 | item.perm
            if item.existed and item.remote_file not in deleted_set:
                cmds.append(f"rm {qr}")
            cmds.extend(
                [
                    f"write {ql} {qr}",
                    f"set_inode_field {qr} mode 0{ext4_mode:o}",
                    f"set_inode_field {qr} uid 0",
                    f"set_inode_field {qr} gid 0",
                ]
            )

        if cmds:
            self.run_debugfs(cmds, write=True)

        if verify_readback and (deleted_targets or files_to_write):
            overwritten = {w.remote_file for w in files_to_write}
            for dp in deleted_targets:
                if dp not in overwritten and self.path_exists(dp):
                    raise RuntimeError(f"Post-write check failed on {self.path.name}: deleted path {dp} still exists")
            with tempfile.TemporaryDirectory(prefix="fw_ext4_verify_") as tmp:
                rb = Path(tmp) / "readback.bin"
                for item in files_to_write:
                    st = self.stat_path(item.remote_file)
                    if st is None:
                        raise RuntimeError(f"Post-write check failed on {self.path.name}: {item.remote_file} missing")
                    if st.size != item.size:
                        raise RuntimeError(
                            f"Post-write size mismatch for {item.remote_file}: expected {item.size}, got {st.size}"
                        )
                    actual_perm = st.mode & 0o7777
                    if actual_perm != item.perm:
                        raise RuntimeError(
                            f"Post-write mode mismatch for {item.remote_file}: "
                            f"expected {oct(item.perm)}, got {oct(actual_perm)}"
                        )
                    self.dump_file_to(item.remote_file, rb)
                    rb_sha, rb_size = _sha256_file(rb)
                    if rb_size != item.size or rb_sha != item.sha256:
                        raise RuntimeError(
                            f"Post-write SHA-256 mismatch for {item.remote_file}: "
                            f"expected {item.sha256}, got {rb_sha}"
                        )

        return {
            "deleted": len(deleted_targets),
            "written": len(files_to_write),
            "dirs_created": len(dirs_to_create),
        }

    def fsck(self) -> str:
        res = subprocess.run([self._e2fsck, "-fn", str(self.path)], capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise RuntimeError(
                f"e2fsck -fn failed on {self.path.name} (exit {res.returncode}):\n{res.stdout}\n{res.stderr}"
            )
        return res.stdout.strip()

    def assert_mountable_read_write(self) -> Ext4Features:
        """Check the properties a read-write mount needs — not just fs integrity.

        `e2fsck -fn` exits 0 on a `shared_blocks` image, so fsck alone says nothing about
        whether the slot can be mounted. This checks the superblock for read-write
        blockers and for a journal; missing either is how a `/md` mount fails *after* the
        slot has already been committed.
        """
        feats = self.features()
        problems = feats.read_write_blockers()
        if feats.is_ext4 and not feats.has_journal:
            problems.append("no has_journal: a read-write ext4 mount replays or creates no journal")
        if problems:
            raise Ext4UnsafeImageError(
                f"{self.path.name} is not safely mountable read-write: " + "; ".join(problems)
            )
        return feats
