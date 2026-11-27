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
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

_E2FS_SEARCH_DIRS = (
    "/opt/homebrew/opt/e2fsprogs/sbin",
    "/opt/homebrew/opt/e2fsprogs/bin",
    "/usr/local/opt/e2fsprogs/sbin",
    "/usr/local/opt/e2fsprogs/bin",
    "/usr/sbin",
    "/sbin",
)

_MIN_FREE_INODES = 32
_STAT_INODE_RE = re.compile(
    r"Inode:\s*(?P<inode>\d+)\s+Type:\s*(?P<type>\S+)\s+Mode:\s*(?P<mode>[0-7]+)"
)
_STAT_SIZE_RE = re.compile(r"Size:\s*(?P<size>\d+)")


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
    ) -> Dict[str, int]:
        """Apply file deletions and a directory overlay onto the ext4 image with SHA-256 readback."""
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
