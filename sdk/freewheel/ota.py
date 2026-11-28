"""Owner-side firmware retrieval, package verification, and OTA upload.

This module replaces everything `benibust.py` used to take from an external SDK,
using only the Python standard library plus (optionally) this SDK's own
`MondoClient` for the Zenoh `/cmd/ota/*` control channel:

  * **Recovering your key** — `md_upgrade` (`:8085`) authenticates reads with a
    static retail *media bearer*. The value is a plaintext constant inside your own
    copy of `MondoApp.apk`; we never ship it in this repo, only the SHA-256 digest
    the robot itself checks against. `extract-token` sweeps your APK and verifies a
    candidate against that digest, so you can prove you recovered the right string.

  * **Fetching your firmware** — `pull-firmware` walks `md_upgrade`'s work
    directory (`GET /list` + `GET /files/*`) and downloads the staged
    `all_in_one.zip` and `extract_*/x5_0300/hbre.img` the robot already holds,
    resumably, straight into `beni_fw/`.

  * **Verifying and flashing** — `verify_package` re-implements the anti-brick
    structural checks, and `upload_firmware` mints a live V2 `Upload-Token` over
    Zenoh and streams the package with resumable TUS 1.0.0, then polls to `READY`
    and (optionally) triggers the install.

CLI (all self-contained):

    python -m freewheel.ota doctor
    python -m freewheel.ota extract-token ~/Downloads/MondoApp.apk
    python -m freewheel.ota set-token            # paste a token you captured yourself
    python -m freewheel.ota inventory --host 192.168.7.1
    python -m freewheel.ota pull-firmware --host 192.168.7.1 --out beni_fw
    python -m freewheel.ota verify V26.11.19.37_lz110_freewheel.zip --base beni_fw/current_26.11/all_in_one.zip
    python -m freewheel.ota upload PKG.zip --host 192.168.7.1 --install
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import http.client
import json
import os
import re
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# The media bearer is global, static, and identical on every retail unit. The robot
# compares sha256(token) to this digest, so publishing the digest is safe: it lets an
# owner *prove* the token they recovered from their own app is the real one, without
# this repository ever carrying the secret itself.
MEDIA_TOKEN_SHA256 = "5500fdb05dcfc31e9ddd00b4892d4ded351227b09b8796ca8bb8cdd4b727b0e5"

DEFAULT_OTA_PORT = 8085
DEFAULT_UCP_PORT = 9007
MIN_SAFE_BATTERY_PCT = 30

# OtaUpgradeControlReqData.controlCmd
OTA_CMD_START = 0
OTA_CMD_CANCEL = 1
OTA_CMD_CONFIRM_COMPLETE = 2
OTA_CMD_QUERY = 3
OTA_CMD_INSTALL = 4

UNSAFE_ACTIVE_OTA_STATES = frozenset(
    {"INSTALLING", "AWAITING_REBOOT", "WAITING_REBOOT", "CONFIRMING", "RECOVERY_REQUIRED"}
)

# Robot posture values where the leg motors are actively supporting or moving the robot.
UNSAFE_MOTION_STATES: Dict[int, str] = {
    1: "STANDING_UP",
    2: "BALANCING",
    3: "FOLDING",
    4: "JUMPING",
    5: "FLIPPING",
    6: "DOCKING",
}

# Artifacts `md_upgrade` stages on the robot that an owner needs for a build.
FIRMWARE_ARTIFACTS = ("all_in_one.zip", "hbre.img", "system.img", "mondo.img", "last_package.toml")

# The first entry is this SDK's own; the rest are pre-1.0 names kept so an existing
# install keeps resolving its token. They are compatibility identifiers, not branding.
_TOKEN_ENV_NAMES = ("FREEWHEEL_MEDIA_TOKEN",)
_LEGACY_TOKEN_ENV_NAMES = ("NEBI_HTTP_BEARER_TOKEN", "PYNEBI_MEDIA_TOKEN")
TOKEN_ENV_VARS = _TOKEN_ENV_NAMES + _LEGACY_TOKEN_ENV_NAMES
LEGACY_TOKEN_ENV_VARS = _LEGACY_TOKEN_ENV_NAMES
_LEGACY_CONFIG_DIR = "pynebi"
_LEGACY_DEVICE_ID_ENV = "NEBI_DEVICE_ID"   # pre-1.0 name, still read for existing installs

STREAM_CHUNK = 1 << 20


# ---------------------------------------------------------------------------
# Media token: location, resolution, recovery from your own MondoApp.apk
# ---------------------------------------------------------------------------

def freewheel_config_dir() -> Path:
    return Path(os.environ.get("FREEWHEEL_CONFIG_DIR") or (Path.home() / ".config" / "freewheel"))


def default_media_token_path() -> Path:
    return freewheel_config_dir() / "media_token"


def legacy_media_token_path() -> Path:
    return Path.home() / ".config" / _LEGACY_CONFIG_DIR / "media_token"


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_known_media_token(token: str, expected_sha256: str = MEDIA_TOKEN_SHA256) -> bool:
    return bool(token) and token_digest(token.strip()) == expected_sha256.lower()


def resolve_media_token(explicit: Optional[str] = None, *, allow_missing: bool = True) -> str:
    """Resolve the `:8085` bearer: explicit > env > `~/.config/freewheel/media_token` > legacy path."""
    if explicit:
        return explicit.strip()
    for var in TOKEN_ENV_VARS:
        val = os.environ.get(var, "").strip()
        if val:
            return val
    for path in (default_media_token_path(), legacy_media_token_path()):
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    if allow_missing:
        return ""
    raise FileNotFoundError(
        "No media bearer token found. Recover it from your own copy of the app:\n"
        "  python -m freewheel.ota extract-token ~/Downloads/MondoApp.apk\n"
        f"which writes {default_media_token_path()} (mode 0600)."
    )


def save_media_token(token: str, path: Optional[Path] = None, *, expected_sha256: str = MEDIA_TOKEN_SHA256) -> Path:
    """Persist a verified token atomically with mode 0600."""
    token = token.strip()
    if not token:
        raise ValueError("refusing to save an empty media token")
    if expected_sha256 and not is_known_media_token(token, expected_sha256):
        raise ValueError(
            f"candidate token does not match sha256 {expected_sha256} "
            f"(got {token_digest(token)}); refusing to save a wrong key"
        )
    target = Path(path) if path else default_media_token_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".media_token.", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(token + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    os.chmod(target, 0o600)
    return target


_PRINTABLE_RUN_RE = re.compile(rb"[\x21-\x7e]{8,4096}")
_MIN_CANDIDATE = 8
_MAX_CANDIDATE = 512
_TRIM_CHARS = "\"'` \t\r\n\x00,;:()[]{}=<>|&+*/\\"


def _candidates(run: bytes) -> Iterable[bytes]:
    """Yield plausible token spellings from one printable ASCII run."""
    seen: set = set()

    def emit(blob: bytes) -> Iterable[bytes]:
        if _MIN_CANDIDATE <= len(blob) <= _MAX_CANDIDATE and blob not in seen:
            seen.add(blob)
            yield blob

    text = run.decode("ascii", errors="ignore")
    for variant in (
        text,
        text.strip(_TRIM_CHARS),
        text.lstrip("Bearer").lstrip(_TRIM_CHARS),
        text.split("Bearer ", 1)[-1].strip(_TRIM_CHARS),
    ):
        yield from emit(variant.encode())

    for piece in re.split(r"[\s\"'`,;:()\[\]{}=<>|&+*/\\]+", text):
        piece = piece.strip(_TRIM_CHARS)
        if piece:
            yield from emit(piece.encode())


_SLIDE_TRIGGER_RE = re.compile(rb"[=:?\"'&,\s]")


def _sliding_candidates(run: bytes) -> Iterable[bytes]:
    """Second pass: substrings of a run, for a literal glued to neighbouring text."""
    text = run.decode("ascii", errors="ignore")
    n = len(text)
    for length in range(_MIN_CANDIDATE, min(n, 128) + 1):
        for start in range(0, n - length + 1):
            yield text[start:start + length].encode()


def _scan_bytes(buf: bytes, carry: bytes, expected: str) -> Tuple[Optional[str], bytes]:
    """Scan a chunk for a candidate whose sha256 matches `expected`; returns (token, new_carry)."""
    data = carry + buf
    last_end = 0
    for m in _PRINTABLE_RUN_RE.finditer(data):
        last_end = m.end()
        run = m.group()
        for cand in _candidates(run):
            if hashlib.sha256(cand).hexdigest() == expected:
                return cand.decode("ascii", errors="replace"), b""
        # A literal glued into a URL/query/assignment still resolves. Short runs are
        # cheap to slide exhaustively; longer ones only when they carry a delimiter
        # (sliding every long identifier would be far too slow on a 600 MB image).
        slide = len(run) <= 64 or (len(run) <= 256 and _SLIDE_TRIGGER_RE.search(run))
        if len(run) >= 16 and slide:
            for cand in _sliding_candidates(run):
                if hashlib.sha256(cand).hexdigest() == expected:
                    return cand.decode("ascii", errors="replace"), b""
    tail = data[last_end:]
    return None, tail[-_MAX_CANDIDATE:]


def _match_in_blob(blob: bytes, expected: str) -> Optional[str]:
    token, _ = _scan_bytes(blob, b"", expected)
    if token:
        return token
    # Fallback: brute-force substrings of every printable run (handles tokens embedded
    # inside a longer literal, e.g. a URL query string in a Flutter asset).
    for m in _PRINTABLE_RUN_RE.finditer(blob):
        run = m.group()
        if len(run) > 2048:
            continue
        for cand in _sliding_candidates(run):
            if hashlib.sha256(cand).hexdigest() == expected:
                return cand.decode("ascii", errors="replace")
    return None


def _scan_stream(fp, expected: str) -> Optional[str]:
    carry = b""
    while True:
        chunk = fp.read(STREAM_CHUNK)
        if not chunk:
            return None
        token, carry = _scan_bytes(chunk, carry, expected)
        if token:
            return token


def _scan_bundle(path: Path, expected: str, say: Callable[[str], None]) -> Optional[str]:
    """Scan every entry of an APK/zip; nested APKs inside a bundle are opened too."""
    with zipfile.ZipFile(path) as zf:
        for info in sorted(zf.infolist(), key=lambda i: -i.file_size):
            if info.is_dir():
                continue
            say(f"scanning {info.filename} ({info.file_size / 1e6:.1f} MB)")
            with zf.open(info) as fp:
                token = _scan_stream(fp, expected)
            if token:
                return token
            if info.filename.lower().endswith(".apk") and info.file_size:
                say(f"  (nested APK {info.filename}; opening)")
                with zf.open(info) as fp, tempfile.SpooledTemporaryFile(max_size=256 << 20) as spool:
                    shutil_copy(fp, spool)
                    spool.seek(0)
                    if zipfile.is_zipfile(spool):
                        with zipfile.ZipFile(spool) as nested:
                            for ni in sorted(nested.infolist(), key=lambda i: -i.file_size):
                                if ni.is_dir():
                                    continue
                                with nested.open(ni) as nfp:
                                    found = _scan_stream(nfp, expected)
                                if found:
                                    return found
    return None


def shutil_copy(src, dst) -> None:
    for chunk in iter(lambda: src.read(STREAM_CHUNK), b""):
        dst.write(chunk)


def extract_media_token_from_apk(
    source: str | Path,
    *,
    save: bool = True,
    save_path: Optional[Path] = None,
    expected_sha256: str = MEDIA_TOKEN_SHA256,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    """Sweep an `.apk`/`.zip`/`.so`/`.dex`/directory for a string whose sha256 matches `expected_sha256`.

    The retail media bearer is a plaintext constant inside the app (SecNeo-protected
    Flutter/Dart, so it lands in `libapp.so` rodata or a DEX string pool). We never
    bundle the value: we hash every printable run we find and compare the digest the
    robot itself uses, so a hit is proof rather than a guess.
    """
    expected = expected_sha256.lower()
    src = Path(source).expanduser()
    if not src.exists():
        raise FileNotFoundError(f"app bundle not found: {src}")
    say = progress or (lambda _m: None)

    def _found(token: str, where: str) -> str:
        say(f"verified media token in {where} (sha256 {expected[:12]}…)")
        if save:
            target = save_media_token(token, save_path, expected_sha256=expected)
            say(f"saved {target} (mode 0600)")
        return token

    if src.is_dir():
        for path in sorted(p for p in src.rglob("*") if p.is_file()):
            size = path.stat().st_size
            if size == 0 or size > 512 * 1024 * 1024:
                continue
            say(f"scanning {path.name} ({size / 1e6:.1f} MB)")
            if zipfile.is_zipfile(path):
                token = _scan_bundle(path, expected, say)
            else:
                with path.open("rb") as fp:
                    token = _scan_stream(fp, expected)
            if token:
                return _found(token, path.name)
        raise LookupError(
            f"no string in {src} hashed to {expected}. Is this the retail MondoApp install "
            "(not a stub/split APK without `lib/arm64-v8a/libapp.so`)?"
        )

    if zipfile.is_zipfile(src):
        token = _scan_bundle(src, expected, say)
        if token:
            return _found(token, src.name)
        raise LookupError(
            f"scanned every entry of {src.name} and none hashed to {expected}. "
            "A split/App-Bundle install needs the base APK plus its `split_config.arm64_v8a.apk`; "
            "pass the folder holding them instead."
        )

    say(f"scanning {src.name} ({src.stat().st_size / 1e6:.1f} MB)")
    blob = src.read_bytes()
    token = _match_in_blob(blob, expected)
    if token:
        return _found(token, src.name)
    raise LookupError(f"no string in {src.name} hashed to {expected}")


# ---------------------------------------------------------------------------
# md_upgrade (:8085) HTTP client — inventory & resumable firmware pull
# ---------------------------------------------------------------------------

class MdUpgradeError(RuntimeError):
    """Raised when `md_upgrade` answers with an error or refuses our credentials."""


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def detect_scheme(host: str, port: int = DEFAULT_OTA_PORT, timeout: float = 5.0) -> str:
    """Probe `md_upgrade` to learn whether it speaks HTTP or HTTPS on this unit."""
    last: Optional[BaseException] = None
    for scheme in ("http", "https"):
        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = _make_connection(host, port, scheme, timeout)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            resp.read()
            if resp.status < 500:
                return scheme
        except Exception as exc:  # noqa: BLE001
            last = exc
        finally:
            if conn is not None:
                conn.close()
    raise ConnectionError(f"could not reach md_upgrade on {host}:{port} over HTTP or HTTPS: {last}")


def _make_connection(host: str, port: int, scheme: str, timeout: float) -> http.client.HTTPConnection:
    if scheme == "https":
        return http.client.HTTPSConnection(host, port=port, timeout=timeout, context=_ssl_context())
    if scheme == "http":
        return http.client.HTTPConnection(host, port=port, timeout=timeout)
    raise ValueError(f"unsupported scheme: {scheme!r}")


@dataclass
class RemoteEntry:
    name: str
    path: str
    is_dir: bool
    size: int


class MdUpgradeClient:
    """Minimal client for the robot's firmware daemon: `/health`, `/list`, `/files/*`, `/v2/upgrades/*`."""

    def __init__(self, host: str = "192.168.7.1", port: int = DEFAULT_OTA_PORT, *,
                 scheme: str = "auto", bearer_token: Optional[str] = None, timeout: float = 30.0):
        self.host = host
        self.port = port
        self.scheme = detect_scheme(host, port) if scheme == "auto" else scheme
        self.bearer_token = resolve_media_token(bearer_token)
        self.timeout = timeout

    # -- low level ---------------------------------------------------------
    def headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h: Dict[str, str] = {}
        if self.bearer_token:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        if extra:
            h.update(extra)
        return h

    def _request(self, method: str, path: str, *, extra_headers: Optional[Dict[str, str]] = None,
                 timeout: Optional[float] = None) -> Tuple[int, str]:
        conn = _make_connection(self.host, self.port, self.scheme, timeout or self.timeout)
        try:
            conn.request(method, path, headers=self.headers(extra_headers))
            resp = conn.getresponse()
            return resp.status, resp.read().decode("utf-8", errors="replace")
        finally:
            conn.close()

    def _json(self, method: str, path: str, **kw) -> Any:
        status, body = self._request(method, path, **kw)
        if status in (401, 403):
            raise MdUpgradeError(
                f"md_upgrade rejected our bearer on {path} (HTTP {status}). "
                "Recover your key with `python -m freewheel.ota extract-token <MondoApp.apk>`."
            )
        if status >= 400:
            raise MdUpgradeError(f"{method} {path} failed (HTTP {status}): {body[:400]}")
        try:
            return json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            return {"raw": body}

    # -- reads -------------------------------------------------------------
    def health(self) -> Any:
        return self._json("GET", "/health", timeout=min(self.timeout, 8.0))

    def list_dir(self, path: str = "") -> List[RemoteEntry]:
        q = urllib.parse.quote(path, safe="/")
        data = self._json("GET", f"/list?path={q}", timeout=min(self.timeout, 20.0))
        entries: List[Any] = []
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            for key in ("files", "entries", "items", "packages"):
                if isinstance(data.get(key), list):
                    entries = data[key]
                    break
        out: List[RemoteEntry] = []
        for item in entries:
            if isinstance(item, str):
                out.append(RemoteEntry(name=item, path=_join(path, item), is_dir=item.endswith("/"), size=-1))
                continue
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("filename") or item.get("path") or "")
            if not name:
                continue
            kind = str(item.get("file_type") or item.get("type") or "").lower()
            is_dir = kind in ("directory", "dir", "folder") or bool(item.get("is_dir"))
            size = int(item.get("size", -1))
            out.append(RemoteEntry(name=name, path=_join(path, name), is_dir=is_dir, size=size))
        return out

    def walk(self, path: str = "", depth: int = 3) -> List[RemoteEntry]:
        found: List[RemoteEntry] = []
        for entry in self.list_dir(path):
            found.append(entry)
            if entry.is_dir and depth > 1:
                found.extend(self.walk(entry.path, depth - 1))
        return found

    def download(self, remote_path: str, dest: str | Path, *,
                 progress: Optional[Callable[[int, int], None]] = None,
                 timeout: Optional[float] = None) -> int:
        """Download one file, resuming with a Range request when a partial copy exists."""
        out = Path(dest)
        out.parent.mkdir(parents=True, exist_ok=True)
        have = out.stat().st_size if out.exists() else 0
        hdrs = self.headers({"Range": f"bytes={have}-"} if have else None)
        url = f"{self.scheme}://{self.host}:{self.port}/files/{urllib.parse.quote(remote_path, safe='/')}"
        req = urllib.request.Request(url, headers=hdrs)
        try:
            resp = urllib.request.urlopen(req, context=_ssl_context(), timeout=timeout or self.timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 416 and have:
                return have                      # already complete
            if exc.code in (401, 403):
                raise MdUpgradeError(
                    f"md_upgrade rejected our bearer downloading {remote_path} (HTTP {exc.code})"
                ) from exc
            raise
        with resp:
            total = int(resp.headers.get("Content-Length") or 0)
            if have and resp.status != 206:
                have = 0                        # server ignored Range: start over
                out.unlink(missing_ok=True)
            done = have
            total = (total + have) if total else 0
            with out.open("ab" if have else "wb") as fp:
                while True:
                    chunk = resp.read(STREAM_CHUNK)
                    if not chunk:
                        break
                    fp.write(chunk)
                    done += len(chunk)
                    if progress is not None:
                        progress(done, total)
        return out.stat().st_size

    # -- V2 upgrade session helpers (TUS 1.0.0) ----------------------------
    def upload_offset(self, upgrade_id: str, upload_token: str,
                      timeout: Optional[float] = None) -> Optional[int]:
        """Ask the robot how many bytes of this session it has (HEAD, then the task JSON)."""
        t = timeout or min(self.timeout, 20.0)
        try:
            conn = _make_connection(self.host, self.port, self.scheme, t)
            try:
                conn.request("HEAD", f"/v2/upgrades/{upgrade_id}/upload",
                             headers=self.headers({"Upload-Token": upload_token,
                                                   "Tus-Resumable": "1.0.0"}))
                resp = conn.getresponse()
                resp.read()
                if resp.status in (200, 204):
                    off = resp.getheader("Upload-Offset")
                    if off is not None and str(off).strip().isdigit():
                        return int(off)
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 - fall through to the JSON state
            pass
        try:
            status, body = self._request("GET", f"/v2/upgrades/{upgrade_id}",
                                         extra_headers={"Upload-Token": upload_token}, timeout=t)
            if status < 400 and body.strip():
                data = json.loads(body)
                for key in ("offset", "received", "uploaded_bytes", "upload_offset"):
                    if isinstance(data.get(key), int):
                        return int(data[key])
        except Exception:  # noqa: BLE001
            pass
        return None

    def patch_slice(self, upgrade_id: str, upload_token: str, path: Path, *,
                    start: int, end: int, file_size: int, io_chunk: int = 1 << 20,
                    timeout: float = 60.0) -> int:
        """Send one TUS `PATCH` covering `[start, end)` of `path`; returns the HTTP status."""
        length = end - start
        conn = _make_connection(self.host, self.port, self.scheme, timeout)
        try:
            conn.putrequest("PATCH", f"/v2/upgrades/{upgrade_id}/upload", skip_accept_encoding=True)
            conn.putheader("Content-Type", "application/offset+octet-stream")
            conn.putheader("Content-Length", str(length))
            conn.putheader("Tus-Resumable", "1.0.0")
            conn.putheader("Upload-Offset", str(start))
            conn.putheader("Upload-Length", str(file_size))
            for k, v in self.headers({"Upload-Token": upload_token}).items():
                conn.putheader(k, v)
            conn.endheaders()
            with path.open("rb") as fh:
                fh.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = fh.read(min(io_chunk, remaining))
                    if not chunk:
                        break
                    conn.send(chunk)
                    remaining -= len(chunk)
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()

    def install(self, upgrade_id: str, upload_token: str,
                timeout: float = 15.0) -> Dict[str, Any]:
        """`POST /v2/upgrades/{id}/install` for a session that has reached `READY`."""
        status, body = self._request(
            "POST", f"/v2/upgrades/{upgrade_id}/install",
            extra_headers={"Upload-Token": upload_token, "Content-Length": "0"}, timeout=timeout,
        )
        if status >= 400:
            raise MdUpgradeError(f"POST /v2/upgrades/{upgrade_id}/install failed (HTTP {status}): {body[:400]}")
        try:
            return json.loads(body) if body.strip() else {"status": status}
        except json.JSONDecodeError:
            return {"status": status, "body": body}

    # -- owner firmware inventory -----------------------------------------
    def firmware_inventory(self, *, walk_depth: int = 3) -> Dict[str, Any]:
        """Find the staged firmware artifacts `md_upgrade` keeps after an OTA.

        The daemon unpacks each package into `extract_<uuid>/` and keeps the outer
        archive under `tmp/`, so a robot that has ever been updated usually still
        holds a full copy of the very images an owner needs.
        """
        roots = self.list_dir("")
        dirs = [e.name for e in roots if e.is_dir]
        entries: List[RemoteEntry] = list(roots)
        for d in ("tmp", *[d for d in dirs if d.startswith("extract_")]):
            try:
                entries.extend(self.walk(d, walk_depth))
            except MdUpgradeError:
                continue

        artifacts: List[Dict[str, Any]] = []
        for e in entries:
            if e.is_dir:
                continue
            if Path(e.name).name in FIRMWARE_ARTIFACTS:
                artifacts.append({"name": e.name, "path": e.path, "size": e.size})

        by_name: Dict[str, List[Dict[str, Any]]] = {}
        for a in artifacts:
            by_name.setdefault(Path(a["name"]).name, []).append(a)

        return {
            "host": self.host,
            "scheme": self.scheme,
            "roots": dirs,
            "files": [{"path": e.path, "size": e.size} for e in entries if not e.is_dir],
            "artifacts": artifacts,
            "by_name": by_name,
            "extract_dirs": [d for d in dirs if d.startswith("extract_")],
        }


def _join(parent: str, name: str) -> str:
    if not parent:
        return name
    return f"{parent.rstrip('/')}/{name}"


def _safe_remote_name(name: str) -> str:
    if name in ("", ".", "..") or "/" in name or "\x00" in name:
        raise MdUpgradeError(f"refusing unsafe entry name from robot: {name!r}")
    return name


def pull_robot_firmware(
    host: str = "192.168.7.1",
    *,
    out_dir: str | Path = "beni_fw",
    port: int = DEFAULT_OTA_PORT,
    scheme: str = "auto",
    bearer_token: Optional[str] = None,
    only: Optional[Iterable[str]] = None,
    progress: Optional[Callable[[str, int, int], None]] = None,
) -> Dict[str, Any]:
    """Mirror the robot's staged `all_in_one.zip` / `hbre.img` into `beni_fw/`.

    `all_in_one.zip` lands at `beni_fw/current_26.11/all_in_one.zip` (the path
    `benibust.py` auto-discovers) and every other artifact keeps the robot's
    own `extract_<uuid>/x5_0300/...` layout under `beni_fw/mirror/`.
    """
    client = MdUpgradeClient(host, port, scheme=scheme, bearer_token=bearer_token)
    inv = client.firmware_inventory()
    wanted = {w.lower() for w in only} if only else set(FIRMWARE_ARTIFACTS)
    out = Path(out_dir)
    downloaded: List[Dict[str, Any]] = []

    def _dest_for(entry: Dict[str, Any]) -> Path:
        name = Path(entry["name"]).name
        remote = entry["path"]
        if name == "all_in_one.zip" and remote.count("/") <= 1:
            return out / "current_26.11" / "all_in_one.zip"
        if remote.startswith("extract_"):
            return out / "mirror" / remote
        return out / "mirror" / "tmp" / Path(remote).name

    for entry in inv["artifacts"]:
        base = Path(entry["name"]).name
        if base.lower() not in wanted:
            continue
        dest = _dest_for(entry)
        already = dest.is_file() and (entry["size"] < 0 or dest.stat().st_size == entry["size"])
        if already:
            downloaded.append({"name": base, "path": str(dest), "size": entry["size"], "skipped": True})
            continue

        def _cb(done: int, total: int, _b: str = base) -> None:
            if progress is not None:
                progress(_b, done, total)

        got = client.download(entry["path"], dest, progress=_cb)
        if entry["size"] >= 0 and got != entry["size"]:
            raise MdUpgradeError(
                f"{base}: downloaded {got} bytes but the robot lists {entry['size']} — re-run to resume"
            )
        downloaded.append({"name": base, "path": str(dest), "size": got, "skipped": False})

    return {
        "host": host,
        "out_dir": str(out),
        "downloaded": downloaded,
        "missing": [n for n in FIRMWARE_ARTIFACTS if n.lower() in wanted and n not in inv["by_name"]],
        "inventory": inv,
    }


def pull_work_tree(
    host: str = "192.168.7.1",
    *,
    out_dir: str | Path = "beni_fw/dump",
    port: int = DEFAULT_OTA_PORT,
    scheme: str = "auto",
    bearer_token: Optional[str] = None,
    start: str = "",
    max_depth: int = 4,
    progress: Optional[Callable[[str, int, int], None]] = None,
) -> Dict[str, Any]:
    """Enumerate `md_upgrade`'s work directory and grab **everything** in it.

    `/files/*` is sandboxed to the daemon's own work dir, but `/list?path=` enumerates
    any subdirectory, so the whole tree — the outer archives under `tmp/` and every
    unpacked `extract_<uuid>/` — is reachable with a bearer. That is how the firmware
    was first captured: enumerate, then pull each entry, skipping files already local
    with the right size (so a dropped link just needs a re-run).
    """
    client = MdUpgradeClient(host, port, scheme=scheme, bearer_token=bearer_token)
    out = Path(out_dir)
    entries = [e for e in client.walk(start, depth=max_depth) if not e.is_dir]

    pulled: List[Dict[str, Any]] = []
    failures: List[Dict[str, str]] = []
    for entry in entries:
        rel = entry.path if not start else entry.path[len(start.rstrip("/")):].lstrip("/")
        dest = out / rel
        if dest.is_file() and entry.size >= 0 and dest.stat().st_size == entry.size:
            pulled.append({"path": entry.path, "local": str(dest), "size": entry.size, "skipped": True})
            continue

        def _cb(done: int, total: int, _p: str = entry.path) -> None:
            if progress is not None:
                progress(_p, done, total)

        try:
            got = client.download(entry.path, dest, progress=_cb)
        except Exception as exc:  # noqa: BLE001 - keep going, report at the end
            failures.append({"path": entry.path, "error": f"{type(exc).__name__}: {exc}"})
            continue
        if entry.size >= 0 and got != entry.size:
            failures.append({
                "path": entry.path,
                "error": f"got {got} bytes, robot lists {entry.size} — re-run to resume",
            })
            continue
        pulled.append({"path": entry.path, "local": str(dest), "size": got, "skipped": False})

    return {
        "host": host,
        "out_dir": str(out),
        "start": start,
        "files": pulled,
        "failures": failures,
        "total_bytes": sum(f["size"] for f in pulled if f["size"] > 0),
    }


# ---------------------------------------------------------------------------
# Direct partition dump (rooted robot over SSH)
# ---------------------------------------------------------------------------

# hbre is a fixed 150 MiB slot and the only partition Freewheel rewrites; md_upgrade
# md5-checks the whole range, so a dump must be exactly this long.
HBRE_PARTITION_BYTES = 157_286_400
KNOWN_PARTITION_BYTES: Dict[str, int] = {"hbre": HBRE_PARTITION_BYTES}
_BY_NAME_DIR = "/dev/block/platform/by-name"


def _ssh_argv(host: str, *, port: int, key: Optional[str]) -> List[str]:
    key_path = Path(key).expanduser() if key else Path.home() / ".ssh" / "freewheel_ed25519"
    return [
        "ssh", "-p", str(port), "-i", str(key_path),
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=8", f"root@{host}",
    ]


def dump_partition(
    partition: str = "hbre",
    *,
    host: str,
    ssh_port: int = 2222,
    ssh_key: Optional[str] = None,
    slot: str = "current",
    out: Optional[str | Path] = None,
    expected_size: Optional[int] = None,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Any]:
    """`dd` one partition off a rooted robot over SSH into a local image.

    Reads the raw block device, so the result is byte-exact — including the A/B slot
    the robot is *not* currently running, which is where an untouched stock image
    lives after a Freewheel flash. That is the most faithful source for a build.

    `slot="current"` follows `by-name/<part>` (whatever slot booted). Use `"a"`/`"b"`
    to pin one explicitly, which is how you recover the pristine image from the
    inactive slot while running a modified `hbre`.
    """
    if partition in ("", ".", "..") or "/" in partition or "\x00" in partition:
        raise ValueError(f"invalid partition name: {partition!r}")
    if slot not in ("current", "a", "b"):
        raise ValueError(f"slot must be current|a|b, not {slot!r}")

    node = f"{_BY_NAME_DIR}/{partition}" if slot == "current" else f"{_BY_NAME_DIR}/{partition}_{slot}"
    want = expected_size if expected_size is not None else KNOWN_PARTITION_BYTES.get(partition)
    dest = Path(out) if out else Path("beni_fw") / "dump" / f"{partition}.img"
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Never destroy an existing image until a replacement has been read *and* validated:
    # the rollback path tells owners to keep this file as their pristine copy, so a
    # failed transfer must leave it untouched.
    staged = dest.with_name(dest.name + ".partial")
    staged.unlink(missing_ok=True)
    had_previous = dest.is_file()
    previous_bytes = dest.stat().st_size if had_previous else 0

    ssh = _ssh_argv(host, port=ssh_port, key=ssh_key)

    def _fail(msg: str) -> None:
        staged.unlink(missing_ok=True)
        kept = (f" — existing {dest.name} ({previous_bytes:,} bytes) left untouched"
                if had_previous else "")
        raise RuntimeError(msg + kept)

    # Resolve what the node points at and how big it is, so a truncated read can't
    # masquerade as a valid image.
    probe = subprocess.run(
        ssh + [f"readlink -f {node}; blockdev --getsize64 {node} 2>/dev/null || "
               f"stat -c %s {node}"],
        capture_output=True, text=True, timeout=30,
    )
    if probe.returncode != 0:
        _fail(
            f"cannot read {node} over SSH: {(probe.stderr or probe.stdout).strip()}\n"
            "  Needs a root shell (benibust.py) and a readable /dev/block path."
        )
    lines = [ln.strip() for ln in probe.stdout.splitlines() if ln.strip()]
    resolved = lines[0] if lines else node
    remote_size: Optional[int] = None
    for ln in reversed(lines):
        if ln.isdigit():
            remote_size = int(ln)
            break

    total = remote_size or want or 0
    proc = subprocess.Popen(ssh + [f"dd if={node} bs=1M 2>/dev/null"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    got = 0
    assert proc.stdout is not None
    try:
        with staged.open("wb") as fp:
            while True:
                chunk = proc.stdout.read(STREAM_CHUNK)
                if not chunk:
                    break
                fp.write(chunk)
                got += len(chunk)
                if progress is not None:
                    progress(got, total)
    finally:
        _out, err = proc.communicate()
    if proc.returncode != 0:
        _fail(f"dd over SSH failed: {(err or b'').decode('utf-8', 'replace').strip()}")

    digest = sha256_file(staged)
    notes: List[str] = []
    if want is not None and got != want:
        notes.append(
            f"expected {want:,} bytes for the {partition} partition but read {got:,}"
        )
    if remote_size is not None and got != remote_size:
        notes.append(f"robot reports {remote_size:,} bytes but we read {got:,}")

    if notes:
        # A short/bogus read is not a usable image: keep it aside for inspection but
        # do not let it replace the good copy.
        kept_name = staged.name
        kept = (f"; existing {dest.name} ({previous_bytes:,} bytes) left untouched"
                if had_previous else "")
        return {
            "partition": partition,
            "slot": slot,
            "node": node,
            "resolved": resolved,
            "local": str(staged),
            "bytes": got,
            "expected_bytes": want,
            "sha256": digest,
            "ok": False,
            "notes": notes + [f"rejected read kept at {kept_name} for inspection{kept}"],
        }

    os.replace(staged, dest)
    return {
        "partition": partition,
        "slot": slot,
        "node": node,
        "resolved": resolved,
        "local": str(dest),
        "bytes": got,
        "expected_bytes": want,
        "sha256": digest,
        "ok": True,
        "notes": [],
    }


def check_robot_ota(host: str = "192.168.7.1", port: int = DEFAULT_OTA_PORT, *,                    scheme: str = "auto", bearer_token: Optional[str] = None,
                    timeout: float = 5.0) -> Dict[str, Any]:
    """Query `/health` and `/list` on the robot's firmware daemon."""
    client = MdUpgradeClient(host, port, scheme=scheme, bearer_token=bearer_token, timeout=timeout)
    out: Dict[str, Any] = {"scheme": client.scheme, "host": host, "port": port}
    for path, key in (("/health", "health"), ("/list", "packages")):
        try:
            out[key] = client._json("GET", path, timeout=timeout)  # noqa: SLF001 — trivial wrapper
        except Exception as exc:  # noqa: BLE001
            out[key] = {"error": f"{type(exc).__name__}: {exc}"}
    return out


# ---------------------------------------------------------------------------
# Package verification (anti-brick gates)
# ---------------------------------------------------------------------------

PROTECTED_X5_FILES = frozenset(
    {"miniboot.img", "uboot.img", "vbmeta.img", "boot.img", "system.img", "gpt.conf", "ota_process"}
)

CRITICAL_HBRE_PATHS = frozenset({"/bin/ota_tool"})
CRITICAL_MONDO_BINARIES = (
    "/bin/md_sys",
    "/bin/md_upgrade",
    "/bin/md_videotrans",
    "/bin/md_netmanager",
    "/bin/md_relay",
)
CRITICAL_MONDO_PATHS = frozenset({*CRITICAL_MONDO_BINARIES, "/etc/md_upgrade_config.LZ110.toml"})

EM_AARCH64 = 183
PART_FILENAME_RE = re.compile(
    r"^(?P<prefix>[A-Za-z0-9]+)_(?P<part>[0-9A-Fa-f]{4})_V(?P<version>\d+\.\d+\.\d+\.\d+)"
    r"_(?P<date>\d+)\.(?P<suffix>.+)$"
)


class SafetyValidationError(ValueError):
    """Raised when a package or patch input fails an anti-brick safety gate."""


@dataclass
class PackageVerificationReport:
    zip_path: Path
    package_version: str
    manifest_name: str
    x5_entry_name: Optional[str] = None
    verified_modules: int = 0
    verified_x5_partitions: List[str] = field(default_factory=list)
    ota_process_mode: Optional[int] = None
    warnings: List[str] = field(default_factory=list)


def verify_aarch64_elf_header(hdr: bytes, label: str) -> None:
    """Require a 64-bit little-endian ARM Linux ELF (`e_machine == 183`)."""
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
        raise SafetyValidationError(f"{label}: expected an ELF header (\\x7fELF), got {hdr[:8]!r}")
    ei_class, ei_data = hdr[4], hdr[5]
    if ei_class != 2 or ei_data != 1:
        raise SafetyValidationError(
            f"{label}: expected 64-bit little-endian ELF (class=2, data=1), got class={ei_class}, data={ei_data}"
        )
    e_machine = struct.unpack_from("<H", hdr, 18)[0]
    if e_machine != EM_AARCH64:
        raise SafetyValidationError(
            f"{label}: wrong architecture (e_machine={e_machine}, expected {EM_AARCH64} = AArch64)"
        )


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fp:
        for chunk in iter(lambda: fp.read(STREAM_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: str | Path) -> Tuple[str, int]:
    h = hashlib.md5()
    total = 0
    with Path(path).open("rb") as fp:
        for chunk in iter(lambda: fp.read(STREAM_CHUNK), b""):
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def parse_mass_cfg(raw: bytes) -> Dict[str, Any]:
    """Parse a `.mass.cfg.plain.unsign` TOML manifest (stdlib `tomllib`, small fallback)."""
    text = raw.decode("utf-8")
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
        return _mini_toml(text)
    return tomllib.loads(text)


def _mini_toml(text: str) -> Dict[str, Any]:
    """Tiny TOML reader for `[table]` / `[[array]]` / `key = value` — enough for mass.cfg."""
    root: Dict[str, Any] = {}
    cur: Any = root
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[[") and line.endswith("]]"):
            table = line[2:-2].strip()
            arr = root.setdefault(table, [])
            if not isinstance(arr, list):
                raise ValueError(f"manifest: {table!r} is not an array of tables")
            cur = {}
            arr.append(cur)
            continue
        if line.startswith("[") and line.endswith("]"):
            table = line[1:-1].strip()
            cur = root.setdefault(table, {})
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        val = val.strip()
        if val.startswith(("'", '"')) and val[-1:] == val[0]:
            cur[key.strip()] = val[1:-1]
        elif val.lower() in ("true", "false"):
            cur[key.strip()] = val.lower() == "true"
        else:
            try:
                cur[key.strip()] = int(val)
            except ValueError:
                cur[key.strip()] = val
    return root


def _hash_zip_entry(zf: zipfile.ZipFile, name: str, algo: str = "sha256",
                    scope_bytes: Optional[int] = None) -> Tuple[str, int]:
    digest = hashlib.new(algo)
    total = 0
    remaining = scope_bytes
    with zf.open(name, "r") as fp:
        while True:
            to_read = STREAM_CHUNK if remaining is None else min(STREAM_CHUNK, remaining)
            if remaining is not None and to_read <= 0:
                break
            chunk = fp.read(to_read)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return digest.hexdigest(), total


def _open_nested_zip(outer: zipfile.ZipFile, entry: str, spool) -> zipfile.ZipFile:
    spool.seek(0)
    spool.truncate(0)
    with outer.open(entry, "r") as fp:
        for chunk in iter(lambda: fp.read(STREAM_CHUNK), b""):
            spool.write(chunk)
    spool.seek(0)
    return zipfile.ZipFile(spool, "r")


# ---------------------------------------------------------------------------
# Preflight guards
#
# These encode the two failure modes that cost a real robot its only booting slot:
#
#   1. A `shared_blocks` (read-only, deduplicated) `mondo.img` paired with a
#      `system.img` whose `/etc/hb-fstab` still mounts `/md` read-write. The kernel
#      refuses the mount, `/md` never comes up, and everything that lives on it dies.
#   2. A package stitched from two firmware builds, which is how that pairing gets
#      made in the first place.
#
# Both are cheap to check: the ext4 feature words are in the first 2 KiB of an image,
# and `/etc/hb-fstab` is a small text file.
# ---------------------------------------------------------------------------

MONDO_IMG = "mondo.img"
SYSTEM_IMG = "system.img"
HB_FSTAB_PATH = "/etc/hb-fstab"
HB_FSTAB_FALLBACK_PATHS = ("/etc/fstab",) + tuple(f"/etc/init.d/S{seq}mountall" for seq in range(60, 70))

# Paths that gate committing the booted slot as good. Firmware V26.11.19.01 added
# `/run/lz100-mondo-apps-ready` to `S99ota_update_check.sh`; the older script ran
# `ota_tool -b` unconditionally, which commits a broken slot before anything can roll
# it back.
SLOT_COMMIT_SCRIPT = "/etc/init.d/S99ota_update_check.sh"
SLOT_COMMIT_GATE = "/run/lz100-mondo-apps-ready"
SLOT_COMMIT_GATE_MARKERS = ("lz100-mondo-apps-ready", "lz100-mondo-check")

SLOT_COMMIT_UNKNOWN_BANNER = (
    "\n"
    "  ############################################################\n"
    "  #  SLOT-COMMIT GATING NOT CONFIRMED HEALTHY                 #\n"
    "  ############################################################\n"
    "  We could not inspect the target's /etc/init.d/S99ota_update_check.sh,\n"
    "  so we cannot tell whether a slot that boots without /md is committed as\n"
    "  `successful_boot` anyway. Firmware up to V26.10.x ran `ota_tool -b`\n"
    "  unconditionally, which silently disables U-Boot's A/B auto-rollback: the\n"
    "  robot keeps the broken slot through power cycles instead of falling back.\n"
    "  Before relying on rollback: boot once, confirm /run/lz100-mondo-apps-ready\n"
    "  gating exists, then power-cycle twice and confirm the slot counter is\n"
    "  decrementing (ota_tool -g).\n"
)


def x5_image_features(x5: zipfile.ZipFile, name: str) -> Optional[Any]:
    """Superblock features of one image inside an unpacked 0300 zip, without extracting it."""
    from . import ext4

    if name not in x5.namelist():
        return None
    with x5.open(name, "r") as fp:
        feats = ext4.read_superblock(fp)
    return feats if feats.is_ext4 else None


def _x5_member_text(x5: zipfile.ZipFile, image: str, remote_path: str) -> Optional[str]:
    """Read a small text file out of an ext4 image inside the zip (streamed, no 1 GB copy retained)."""
    from . import ext4

    if image not in x5.namelist():
        return None
    with tempfile.TemporaryDirectory(prefix="fw_fstab_") as tmp:
        local = Path(tmp) / Path(image).name
        with x5.open(image, "r") as src, local.open("wb") as dst:
            for chunk in iter(lambda: src.read(STREAM_CHUNK), b""):
                dst.write(chunk)
        try:
            data = ext4.Ext4Image(local).read_file(remote_path)
        except Exception:  # noqa: BLE001 - missing path / unreadable image is "unknown"
            return None
    return data.decode("utf-8", errors="replace")


def system_img_mounts_md_read_write(x5: zipfile.ZipFile) -> Optional[bool]:
    """Does this package's `system.img` mount `/md` read-write?

    `True` = read-write mount options, `False` = explicit read-only options (e.g. `ro`),
    `None` = could not tell.
    """
    for path in (HB_FSTAB_PATH, *HB_FSTAB_FALLBACK_PATHS):
        text = _x5_member_text(x5, SYSTEM_IMG, path)
        if text is None:
            continue
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            fields = line.split()
            if "/md" not in fields and not any(f.startswith("/md") for f in fields[1:2]):
                continue
            # <device> <mountpoint> <fstype> <options> ...
            if len(fields) < 4:
                continue
            options = fields[3].split(",")
            if "ro" in options:
                return False
            return True
    return None


def check_mondo_read_write_pairing(x5: zipfile.ZipFile, *, allow_override: bool = False) -> List[str]:
    """Refuse a read-only `mondo.img` that a read-write-mounting `system.img` would break on.

    Returns advisory notes; raises `SafetyValidationError` for the bricking combination.
    """
    feats = x5_image_features(x5, MONDO_IMG)
    if feats is None or not feats.shared_blocks:
        return []

    mounts_rw = system_img_mounts_md_read_write(x5)
    if mounts_rw is False:
        return []       # dm-verity / ro mount: the pairing is consistent
    if mounts_rw is None:
        return [
            f"{MONDO_IMG} is shared_blocks (RO_COMPAT 0x4000) but this package's {SYSTEM_IMG} "
            "could not be read to confirm /md mounts read-only; if it mounts /md rw the slot "
            "will not boot"
        ]
    if allow_override:
        return [
            f"{MONDO_IMG} is shared_blocks but {SYSTEM_IMG} mounts /md read-write "
            "(overridden with --allow-unsafe-mondo-pairing)"
        ]
    raise SafetyValidationError(
        f"refusing package: {MONDO_IMG} is shared_blocks (RO_COMPAT 0x4000, a deduplicated "
        f"read-only ext4) while this package's {SYSTEM_IMG} mounts /md read-write via "
        f"{HB_FSTAB_PATH}. The kernel refuses an rw mount of a shared_blocks filesystem "
        "(`EXT4-fs: couldn't mount RDWR because of unsupported optional features (4000)`), "
        "/md never mounts, and the slot boots into a dead robot. Ship a system.img that "
        "mounts /md read-only behind dm-verity, or use a journaled, non-shared_blocks "
        f"{MONDO_IMG}. Verify a read-write mount on the robot from the good slot before flashing."
    )


_INNER_VERSIONED_IMG_RE = re.compile(r".*_V(?P<version>\d+\.\d+\.\d+\.\d+)_\d{8,}\.(?:img|bin)")


def _module_version_claims(zf: zipfile.ZipFile, entries: List[str], manifest_name: str,
                           firmwares: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """Version each *module* asserts, as (source, version).

    Only module-level identities are collected, deliberately:

    * `[package].version` is the release the package ships as, and vendor packages name
      their inner X5 module after the *build* it was cut from — V26.11.19.01 shipped a
      `lz110_0300_V26.10.27.92_...` module, so comparing the two would flag every stock
      package. The same goes for the `0000` manifest entry.
    * `data.json`'s `version` is not the package release either.

    What must agree is the modules with each other: `0300` and `0301` from one release.
    """
    claims: List[Tuple[str, str]] = []
    for name in entries:
        if name == manifest_name or name.endswith("/"):
            continue
        m = PART_FILENAME_RE.match(name)
        if m and m.group("part").upper() != "0000":
            claims.append((f"module {m.group('part').upper()} ({Path(name).name})", m.group("version")))
    return claims


def check_module_build_consistency(claims: List[Tuple[str, str]], *, allow_override: bool = False) -> List[str]:
    """Refuse a package whose modules come from different firmware builds.

    This catches a package stitched together at the module level (an `0301` from one
    release next to an `0300` from another). It cannot catch a mix *inside* the `0300`
    archive — a rebuilt zip carries no vendor version for its images — which is why
    `check_mondo_read_write_pairing` inspects the images themselves rather than trusting
    any version string.
    """
    distinct = sorted({v for _src, v in claims})
    if len(distinct) <= 1:
        return []
    detail = "\n".join(f"    {src}: {ver}" for src, ver in claims)
    if allow_override:
        return ["package mixes modules from different firmware builds (overridden):\n" + detail]
    raise SafetyValidationError(
        "refusing package: it mixes modules from different firmware builds.\n" + detail +
        "\n  A module taken from a newer release than the rest of the slot is how a "
        "read-only mondo.img ends up under a read-write-mounting system.img.\n"
        "  Rebuild every module from one release, or pass --allow-mixed-firmware if you "
        "really intend a hybrid and have confirmed the pairing on hardware."
    )


def note_data_json_version(data: Dict[str, Any], manifest_version: str) -> List[str]:
    """Advisory only: `data.json` naming a different release than the manifest is normal.

    Vendor packages keep the inner build identity there, so this can never be a refusal —
    it is printed so a hand-edited `data.json` is visible rather than silent.
    """
    declared = str(data.get("version", "") or "")
    if not declared or not manifest_version or declared == manifest_version:
        return []
    return [
        f"data.json version {declared!r} differs from the package version {manifest_version!r} "
        "(normal for vendor packages; check it if you edited data.json by hand)"
    ]


def slot_commit_gating_from_system_img(system_img: str | Path) -> str:
    """`"gated"`, `"ungated"`, or `"unknown"` for one `system.img`'s slot-commit script."""
    from . import ext4

    try:
        script = ext4.Ext4Image(system_img).read_file(SLOT_COMMIT_SCRIPT).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - no image, no path, unreadable: all "unknown"
        return "unknown"
    if any(marker in script for marker in SLOT_COMMIT_GATE_MARKERS):
        return "gated"
    if "ota_tool" in script and "-b" in script:
        return "ungated"
    return "unknown"


def format_slot_commit_warning(state: str) -> str:
    """Unmissable banner for a slot-commit gating state that is not known-good."""
    if state == "gated":
        return ""
    if state == "ungated":
        return (
            "\n"
            "  ############################################################\n"
            "  #  TARGET COMMITS SLOTS UNCONDITIONALLY (ota_tool -b)       #\n"
            "  ############################################################\n"
            f"  This package's {SLOT_COMMIT_SCRIPT} runs `ota_tool -b` without checking\n"
            f"  {SLOT_COMMIT_GATE}. The first boot of the new slot marks it\n"
            "  successful_boot=1 no matter how broken it is, so U-Boot's A/B\n"
            "  auto-rollback will NOT fire and power cycling will not recover the robot.\n"
            "  Only flash a change you have already proven boots.\n"
        )
    return SLOT_COMMIT_UNKNOWN_BANNER


def slot_commit_gating_from_base_zip(base_zip: Optional[str | Path]) -> str:
    """Slot-commit gating of the firmware a package will be built/flashed on.

    The state comes from the base package's own `system.img`, which is the script set the
    target will actually run. No base package means no answer: `"unknown"`.
    """
    if base_zip is None:
        return "unknown"
    base = Path(base_zip)
    if not base.is_file() or not zipfile.is_zipfile(base):
        return "unknown"
    try:
        with zipfile.ZipFile(base) as zf:
            with tempfile.TemporaryDirectory(prefix="fw_gate_") as tmp:
                local = Path(tmp) / SYSTEM_IMG

                def _extract_system(src: zipfile.ZipFile) -> bool:
                    if SYSTEM_IMG not in src.namelist():
                        return False
                    with src.open(SYSTEM_IMG, "r") as member, local.open("wb") as dst:
                        for chunk in iter(lambda: member.read(STREAM_CHUNK), b""):
                            dst.write(chunk)
                    return True

                if SYSTEM_IMG in zf.namelist():
                    if not _extract_system(zf):
                        return "unknown"
                else:
                    inner = [
                        n for n in zf.namelist()
                        if "_0300_" in n and n.endswith(".mass.fw.plain.unsign")
                    ]
                    if not inner:
                        return "unknown"
                    with tempfile.TemporaryFile() as spool, _open_nested_zip(zf, inner[0], spool) as x5:
                        if not _extract_system(x5):
                            return "unknown"
                return slot_commit_gating_from_system_img(local)
    except Exception:  # noqa: BLE001 - unreadable base is simply "unknown"
        return "unknown"


def _collect_base_x5_crcs(base_zip_path: Optional[str | Path]) -> Dict[str, Tuple[int, int]]:
    crcs: Dict[str, Tuple[int, int]] = {}
    if base_zip_path is None or not Path(base_zip_path).is_file():
        return crcs
    with zipfile.ZipFile(base_zip_path) as bzf:
        inner = [n for n in bzf.namelist() if "_0300_" in n and n.endswith(".mass.fw.plain.unsign")]
        if not inner:
            return crcs
        with tempfile.TemporaryFile() as spool, _open_nested_zip(bzf, inner[0], spool) as x5:
            for zi in x5.infolist():
                crcs[zi.filename] = (zi.CRC, zi.file_size)
    return crcs


def _verify_outer_modules(zf: zipfile.ZipFile, entries: List[str], manifest_name: str,
                          firmwares: List[Dict[str, Any]]) -> Tuple[int, Optional[str]]:
    by_part: Dict[str, List[str]] = {}
    for name in entries:
        if name == manifest_name or name.endswith("/"):
            continue
        m = PART_FILENAME_RE.match(name)
        if not m:
            raise SafetyValidationError(f"invalid module filename inside the outer ZIP: {name!r}")
        by_part.setdefault(m.group("part").upper(), []).append(name)

    verified = 0
    x5_entry: Optional[str] = None
    for fw in firmwares:
        part = str(fw["part"]).upper()
        matches = by_part.get(part, [])
        if len(matches) != 1:
            raise SafetyValidationError(f"manifest part {part} expects exactly 1 file in the outer ZIP, found {matches}")
        entry = matches[0]
        if part == "0300":
            x5_entry = entry
        expected_size = int(fw["size"])
        cksum = str(fw["checksum"])
        if not cksum.startswith("sha256:"):
            raise SafetyValidationError(f"part {part} checksum must start with 'sha256:', got {cksum!r}")
        expected_hex = cksum.split(":", 1)[1].lower()
        actual_hex, actual_size = _hash_zip_entry(zf, entry, "sha256")
        if actual_size != expected_size:
            raise SafetyValidationError(
                f"part {part} ({entry}) size mismatch: manifest={expected_size}, actual={actual_size}"
            )
        if actual_hex != expected_hex:
            raise SafetyValidationError(
                f"part {part} ({entry}) SHA-256 mismatch: manifest={expected_hex}, actual={actual_hex}"
            )
        verified += 1
    return verified, x5_entry


def _verify_inner_x5(zf: zipfile.ZipFile, x5_entry: str, base_crcs: Dict[str, Tuple[int, int]], *,
                     allow_unsafe: bool, allow_mixed_firmware: bool = False,
                     allow_unsafe_mondo_pairing: bool = False,
                     manifest_version: str = "",
                     module_version_claims: Optional[List[Tuple[str, str]]] = None,
                     warnings: Optional[List[str]] = None) -> Tuple[List[str], Optional[int]]:
    parts: List[str] = []
    ota_mode: Optional[int] = None
    warnings = warnings if warnings is not None else []
    with tempfile.TemporaryFile() as spool, _open_nested_zip(zf, x5_entry, spool) as x5:
        bad = x5.testzip()
        if bad is not None:
            raise SafetyValidationError(f"corrupt entry CRC inside {x5_entry}: {bad}")
        names = set(x5.namelist())
        for req in ("gpt.conf", "data.json"):
            if req not in names:
                raise SafetyValidationError(f"inner 0300 ZIP ({x5_entry}) is missing required file {req!r}")

        if "ota_process" in names:
            info = x5.getinfo("ota_process")
            mode = (info.external_attr >> 16) & 0o7777
            ota_mode = mode
            if info.create_system != 3 or (mode & 0o111) != 0o111:
                raise SafetyValidationError(
                    f"inner 0300 `ota_process` lacks Unix execute bits "
                    f"(create_system={info.create_system}, mode={oct(mode)}); ota_tool execve() would fail"
                )
            with x5.open("ota_process", "r") as fp:
                verify_aarch64_elf_header(fp.read(64), "0300/ota_process")

        if base_crcs and not allow_unsafe:
            for prot in PROTECTED_X5_FILES:
                if prot in base_crcs and prot in names:
                    zi = x5.getinfo(prot)
                    if (zi.CRC, zi.file_size) != base_crcs[prot]:
                        raise SafetyValidationError(
                            f"protected X5 file {prot!r} differs from the base firmware (CRC/size changed) "
                            "without --allow-unsafe-x5-override"
                        )

        data = json.loads(x5.read("data.json").decode("utf-8"))
        part_info: Dict[str, Any] = data.get("partition_info", {})
        update_parts = set(data.get("update_partition", []))
        for part_name, meta in part_info.items():
            imgname = meta.get("imgname")
            if not imgname:
                continue
            if imgname not in names:
                if part_name in update_parts:
                    raise SafetyValidationError(
                        f"data.json lists {part_name!r} ({imgname}) in update_partition but {imgname} "
                        "is missing from the 0300 ZIP"
                    )
                continue
            expected_md5 = str(meta.get("md5sum", {}).get(imgname, "")).lower()
            scope = int(meta.get("md5_scope", {}).get(imgname, -1))
            size = x5.getinfo(imgname).file_size
            if scope <= 0 or scope > size:
                raise SafetyValidationError(f"data.json has invalid md5_scope={scope} for {imgname} (size={size})")
            actual_md5, hashed = _hash_zip_entry(x5, imgname, "md5", scope_bytes=scope)
            if hashed != scope or actual_md5 != expected_md5:
                raise SafetyValidationError(
                    f"data.json MD5 mismatch for {imgname}: expected {expected_md5} (scope={scope}), got {actual_md5}"
                )
            parts.append(part_name)

        # Preflight: a read-only mondo.img must not ship under a read-write-mounting
        # system.img, and a package must not stitch two firmware builds together.
        warnings.extend(note_data_json_version(data, manifest_version))
        warnings.extend(check_module_build_consistency(module_version_claims,
                                                      allow_override=allow_mixed_firmware))
        warnings.extend(check_mondo_read_write_pairing(x5, allow_override=allow_unsafe_mondo_pairing))
    return parts, ota_mode


def verify_package(zip_path: str | Path, *, base_zip_path: Optional[str | Path] = None,
                   allow_unsafe_x5_override: bool = False,
                   allow_mixed_firmware: bool = False,
                   allow_unsafe_mondo_pairing: bool = False,
                   logical_filename: Optional[str] = None) -> PackageVerificationReport:
    """Structurally verify an OTA `.zip`: manifest, module SHA-256, inner MD5 scopes, perms, protected files."""
    pkg = Path(zip_path)
    if not pkg.is_file():
        raise FileNotFoundError(f"firmware ZIP not found: {pkg}")
    name = logical_filename or pkg.name
    if not name.startswith("V") or not name.lower().endswith(".zip"):
        raise SafetyValidationError(
            f"outer ZIP filename must start with 'V' and end with '.zip' (md_upgrade parses the version "
            f"from it), got {name!r}"
        )

    warnings: List[str] = []
    base_crcs = _collect_base_x5_crcs(base_zip_path)
    module_claims: List[Tuple[str, str]] = []

    with zipfile.ZipFile(pkg) as zf:
        bad = zf.testzip()
        if bad is not None:
            raise SafetyValidationError(f"corrupt ZIP entry CRC in {pkg.name}: {bad}")
        entries = zf.namelist()
        cfgs = [n for n in entries if n.endswith(".mass.cfg.plain.unsign")]
        if len(cfgs) != 1:
            raise SafetyValidationError(
                f"expected exactly 1 .mass.cfg.plain.unsign manifest in {pkg.name}, found {cfgs}"
            )
        manifest = cfgs[0]
        cfg = parse_mass_cfg(zf.read(manifest))
        version = str(cfg.get("package", {}).get("version", ""))
        if not version:
            raise SafetyValidationError(f"missing [package].version in {manifest}")
        prefix = f"V{version}_"
        if not name.startswith(prefix):
            warnings.append(f"outer filename {name!r} does not start with {prefix!r}")

        firmwares = cfg.get("firmwares", [])
        if not firmwares:
            raise SafetyValidationError(f"no [[firmwares]] entries in {manifest}")
        modules, x5_entry = _verify_outer_modules(zf, entries, manifest, firmwares)
        module_claims = _module_version_claims(zf, entries, manifest, firmwares)

        x5_parts: List[str] = []
        ota_mode: Optional[int] = None
        if x5_entry is not None:
            x5_parts, ota_mode = _verify_inner_x5(
                zf, x5_entry, base_crcs, allow_unsafe=allow_unsafe_x5_override,
                allow_mixed_firmware=allow_mixed_firmware,
                allow_unsafe_mondo_pairing=allow_unsafe_mondo_pairing,
                manifest_version=version,
                module_version_claims=module_claims, warnings=warnings,
            )

    return PackageVerificationReport(
        zip_path=pkg, package_version=version, manifest_name=manifest, x5_entry_name=x5_entry,
        verified_modules=modules, verified_x5_partitions=x5_parts, ota_process_mode=ota_mode,
        warnings=warnings,
    )


def package_version(zip_path: str | Path) -> str:
    """Read `[package].version` out of a package, falling back to the filename."""
    p = Path(zip_path)
    if zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as zf:
            cfgs = [n for n in zf.namelist() if n.endswith(".mass.cfg.plain.unsign")]
            if cfgs:
                ver = str(parse_mass_cfg(zf.read(cfgs[0])).get("package", {}).get("version", ""))
                if ver:
                    return ver
    return p.stem.lstrip("Vv").split("_", 1)[0]


# ---------------------------------------------------------------------------
# Zenoh control channel: safety preflight, V2 task grant, install
# ---------------------------------------------------------------------------

def _decode_envelope(env_name: str, data_name: str, payload: bytes) -> Optional[Dict[str, Any]]:
    from . import cmd_proto
    try:
        env = cmd_proto.decode_message(env_name, payload)
        if isinstance(env.get("data"), dict) and set(env.keys()) <= {"header", "data"}:
            return env["data"]
    except Exception:  # noqa: BLE001
        pass
    try:
        return cmd_proto.decode_message(data_name, payload)
    except Exception:  # noqa: BLE001
        return None


class _Telemetry:
    """Collects battery + posture from the robot's status puts while a session is open."""

    def __init__(self) -> None:
        from .zenoh_pico import ZenohPicoDecoder
        self._dec = ZenohPicoDecoder()
        self.battery: Optional[Dict[str, Any]] = None
        self.posture: Optional[Dict[str, Any]] = None

    def on_message(self, client, channel: int, payload: bytes) -> None:
        from .zenoh import ALL_TAGS, iter_frames
        from .zenoh_pico import Put
        from . import cmd_proto
        if not payload or payload[0] not in ALL_TAGS:
            return
        try:
            frames = list(iter_frames(payload))
        except Exception:  # noqa: BLE001
            return
        for fr in frames:
            if not fr.is_data:
                continue
            try:
                msgs = self._dec.decode_batch(fr.payload)
            except Exception:  # noqa: BLE001
                continue
            for m in msgs:
                if not isinstance(m, Put):
                    continue
                topic = cmd_proto.canonical_topic(m.keyexpr)
                plain = client.unseal(m.keyexpr, m.payload) if client is not None else m.payload
                if plain is None:
                    continue
                if topic == "status/pmu/osd_status":
                    d = _decode_envelope("PmuOsdStatus", "PmuOsdStatusData", plain)
                    if d is not None:
                        bits = int(d.get("powerBits", 0))
                        self.battery = {
                            "soc": int(d.get("soc", 0)),
                            "charging": bool(bits & 0x02),
                            "docked": bool(bits & 0x04),
                        }
                elif topic == "status/robot/status":
                    d = _decode_envelope("RobotStatus", "RobotStatusData", plain)
                    if d is not None:
                        self.posture = {
                            "robot_state": int(d.get("robotState", 0)),
                            "velocity_cms": abs(int(d.get("velocity", 0))),
                        }

    @property
    def ready(self) -> bool:
        return self.battery is not None


class robot_session:
    """Open a UCP session, negotiate MD-TS if we can, and collect status telemetry.

    The client always streams a **locked** control state, so this can issue `/cmd`
    traffic without any risk of motion.
    """

    def __init__(self, host: str = "192.168.7.1", *, ucp_port: int = DEFAULT_UCP_PORT,
                 identity: Optional[str] = None, security: str = "auto",
                 log: Optional[Callable[[str], None]] = None):
        self.host = host
        self.ucp_port = ucp_port
        self.identity = identity
        self.security = security
        self.log = log or (lambda _m: None)
        self.telemetry = _Telemetry()
        self.client = None

    def __enter__(self):
        from .client import MondoClient
        client = MondoClient(
            host=self.host, port=self.ucp_port, identity=self.identity, security=self.security,
            log=self.log, on_message=lambda ch, payload: self.telemetry.on_message(self.client, ch, payload),
        )
        self.client = client
        client.connect()
        try:
            client.secure()
            client.subscribe("device/**")
        except Exception as exc:  # noqa: BLE001
            self.log(f"session setup warning: {exc}")
        return self

    def __exit__(self, *exc):
        if self.client is not None:
            self.client.close()
        return False

    def wait_telemetry(self, seconds: float = 1.5) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.telemetry.ready:
                return True
            time.sleep(0.05)
        return self.telemetry.ready


def evaluate_safety(
    battery: Optional[Dict[str, Any]],
    posture: Optional[Dict[str, Any]],
    *,
    min_battery_pct: int = MIN_SAFE_BATTERY_PCT,
    ignore_battery: bool = False,
    check_posture: bool = False,
    ignore_posture: bool = False,
) -> List[str]:
    """Pure battery/posture gate. Returns advisory notes; raises `SafetyValidationError` when unsafe.

    Missing telemetry never blocks a flash (older robots don't publish PMU status over
    plaintext `/cmd`), but anything reported must be safe.
    """
    notes: List[str] = []
    if battery and not ignore_battery:
        soc = int(battery.get("soc", 0))
        on_power = bool(battery.get("charging") or battery.get("docked"))
        if soc < min_battery_pct and not on_power:
            raise SafetyValidationError(
                f"battery too low to flash safely: {soc}% (need >= {min_battery_pct}% or the charger). "
                "Dock the robot, or pass --ignore-battery to override."
            )
    elif not battery:
        notes.append("no battery telemetry — battery gate skipped")

    if check_posture and posture and not ignore_posture:
        state = int(posture.get("robot_state", 0))
        vel = int(posture.get("velocity_cms", 0))
        if state in UNSAFE_MOTION_STATES or vel > 5:
            label = UNSAFE_MOTION_STATES.get(state, f"STATE_{state}")
            raise SafetyValidationError(
                f"robot is active/standing ({label}, {vel} cm/s). Fold it on flat ground first, "
                "or pass --ignore-posture."
            )
    return notes


def preflight(host: str = "192.168.7.1", *, ucp_port: int = DEFAULT_UCP_PORT,
              min_battery_pct: int = MIN_SAFE_BATTERY_PCT, ignore_battery: bool = False,
              check_posture: bool = False, ignore_posture: bool = False,
              identity: Optional[str] = None, timeout: float = 8.0,
              log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Battery / posture / in-flight-OTA gates. Raises `SafetyValidationError` when unsafe."""
    with robot_session(host, ucp_port=ucp_port, identity=identity, log=log) as sess:
        sess.wait_telemetry(1.5)
        battery = sess.telemetry.battery
        posture = sess.telemetry.posture
        notes = evaluate_safety(battery, posture, min_battery_pct=min_battery_pct,
                                ignore_battery=ignore_battery, check_posture=check_posture,
                                ignore_posture=ignore_posture)

        previous = ""
        try:
            rsp = sess.client.ota_control(OTA_CMD_QUERY, timeout=min(timeout, 4.0)) or {}
            previous = str((rsp.get("task") or {}).get("state") or "").upper()
        except Exception as exc:  # noqa: BLE001
            log and log(f"OTA state query unavailable: {exc}")
        if previous in UNSAFE_ACTIVE_OTA_STATES:
            raise SafetyValidationError(
                f"the robot already has an OTA in progress ({previous}); refusing to interfere"
            )

        return {"battery": battery, "posture": posture, "previous_task_state": previous}


def create_ota_task(zip_path: str | Path, *, host: str = "192.168.7.1",
                    ucp_port: int = DEFAULT_UCP_PORT, device_id: Optional[str] = None,
                    upgrade_id: Optional[str] = None, min_battery_pct: int = MIN_SAFE_BATTERY_PCT,
                    ignore_battery: bool = False, identity: Optional[str] = None,
                    timeout: float = 10.0,
                    log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Mint a V2 upgrade session over Zenoh; returns `{upgrade_id, upload_grant_token, state, offset}`."""
    path = Path(zip_path)
    if not path.is_file():
        raise FileNotFoundError(f"firmware ZIP not found: {path}")
    size = path.stat().st_size
    sha = sha256_file(path)
    version = package_version(path)
    uid = upgrade_id or str(uuid.uuid4())

    with robot_session(host, ucp_port=ucp_port, identity=identity, log=log) as sess:
        sess.wait_telemetry(1.5)
        battery = sess.telemetry.battery
        notes = evaluate_safety(battery, sess.telemetry.posture, min_battery_pct=min_battery_pct,
                               ignore_battery=ignore_battery)

        serial = device_id or (sess.client.serial_number(timeout=min(timeout, 4.0)) or "")
        if not serial:
            serial = os.environ.get("FREEWHEEL_DEVICE_ID", "") or os.environ.get(_LEGACY_DEVICE_ID_ENV, "")
        if not serial:
            raise RuntimeError(
                "could not resolve the robot serial (device_id); md_upgrade silently drops V2 task "
                "creates without it. Pass --device-id <SERIAL>."
            )

        rsp = sess.client.ota_control(
            OTA_CMD_START,
            task={
                "protocolVersion": 2,
                "upgradeId": uid,
                "deviceId": serial,
                "sha256": sha,
                "size": size,
                "version": version,
                "originalFilename": path.name,
            },
            timeout=timeout,
        ) or {}
        task = rsp.get("task") or {}
        ret = int(rsp.get("retCode", 0) or 0)
        err = str(task.get("errorCode") or "")
        if err.upper() in ("NONE", "OK"):
            err = ""
        if ret != 0 or err:
            raise MdUpgradeError(
                f"md_upgrade rejected the OTA task (retCode={ret}, errorCode={err!r}, "
                f"state={task.get('state')!r})"
            )
        token = str(task.get("uploadGrantToken") or "")
        if not token:
            raise MdUpgradeError(
                "md_upgrade created the task but returned no Upload-Token; the robot may predate the V2 "
                "protocol (try --mode v1)"
            )
        return {
            "upgrade_id": str(task.get("upgradeId") or uid),
            "upload_grant_token": token,
            "state": str(task.get("state") or ""),
            "offset": int(task.get("offset", 0) or 0),
            "device_id": serial,
            "sha256": sha,
            "size": size,
            "version": version,
            "battery": battery,
            "notes": notes,
        }


def trigger_ota_install(host: str = "192.168.7.1", *, upgrade_id: str, upload_token: str,
                        port: int = DEFAULT_OTA_PORT, scheme: str = "auto",
                        bearer_token: Optional[str] = None, ucp_port: int = DEFAULT_UCP_PORT,
                        check_posture: bool = False, ignore_posture: bool = False,
                        ignore_battery: bool = True, identity: Optional[str] = None,
                        timeout: float = 15.0,
                        log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Install a `READY` V2 session: HTTP `POST /v2/upgrades/{id}/install`, else Zenoh `INSTALL`."""
    safety = preflight(host, ucp_port=ucp_port, ignore_battery=ignore_battery,
                       check_posture=check_posture, ignore_posture=ignore_posture,
                       identity=identity, log=log)
    client = MdUpgradeClient(host, port, scheme=scheme, bearer_token=bearer_token)
    try:
        status, body = client._request(  # noqa: SLF001
            "POST", f"/v2/upgrades/{upgrade_id}/install",
            extra_headers={"Upload-Token": upload_token, "Content-Length": "0"}, timeout=timeout,
        )
        if status < 400:
            try:
                parsed = json.loads(body) if body.strip() else {"status": status}
            except json.JSONDecodeError:
                parsed = {"status": status, "body": body}
            return {"method": "v2_http_install", "upgrade_id": upgrade_id, "safety": safety, "response": parsed}
        log and log(f"HTTP install returned {status}; falling back to Zenoh INSTALL")
    except Exception as exc:  # noqa: BLE001
        log and log(f"HTTP install failed ({exc}); falling back to Zenoh INSTALL")

    with robot_session(host, ucp_port=ucp_port, identity=identity, log=log) as sess:
        rsp = sess.client.ota_control(OTA_CMD_INSTALL, task={"protocolVersion": 1, "upgradeId": upgrade_id},
                                      timeout=timeout) or {}
        return {
            "method": "zenoh_control_req",
            "control_cmd": OTA_CMD_INSTALL,
            "ret_code": int(rsp.get("retCode", 0) or 0),
            "stage": int(rsp.get("currentUpgradeStage", 0) or 0),
            "task_state": str((rsp.get("task") or {}).get("state") or ""),
            "error_code": str((rsp.get("task") or {}).get("errorCode") or ""),
            "safety": safety,
        }


def wait_task_ready(host: str, upgrade_id: str, upload_token: str, *, port: int = DEFAULT_OTA_PORT,
                    scheme: str = "auto", bearer_token: Optional[str] = None,
                    timeout: float = 300.0) -> Dict[str, Any]:
    """Poll `GET /v2/upgrades/{id}` until the robot finishes hashing the uploaded package."""
    client = MdUpgradeClient(host, port, scheme=scheme, bearer_token=bearer_token)
    deadline = time.monotonic() + timeout
    last: Dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            status, body = client._request(  # noqa: SLF001
                "GET", f"/v2/upgrades/{upgrade_id}", extra_headers={"Upload-Token": upload_token}, timeout=10.0
            )
            if status >= 400:
                raise MdUpgradeError(f"GET /v2/upgrades/{upgrade_id} failed (HTTP {status}): {body[:300]}")
            last = json.loads(body) if body.strip() else {}
        except (OSError, http.client.HTTPException):
            time.sleep(2.0)          # the daemon may be busy verifying a 600 MB image
            continue
        state = str(last.get("state", "")).upper()
        if state in ("READY", "INSTALLING", "SUCCEEDED"):
            return last
        if state in ("FAILED", "CANCELLED", "EXPIRED", "RECOVERY_REQUIRED"):
            raise MdUpgradeError(f"on-device verification failed in state {state!r}: {last}")
        time.sleep(1.0)
    raise TimeoutError(f"timed out waiting for {upgrade_id} to reach READY; last state: {last}")


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

@dataclass
class UploadResult:
    mode: str
    scheme: str
    host: str
    port: int
    filename: str
    size_bytes: int
    md5: str
    sha256: str
    status_code: int
    response_body: str
    elapsed_sec: float
    upgrade_id: Optional[str] = None
    upload_token: Optional[str] = None
    remote_verified: bool = False
    warnings: List[str] = field(default_factory=list)


def _read_response_after_stream(conn, send_err: Optional[BaseException]) -> Tuple[int, str]:
    try:
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", errors="replace")
    except Exception:
        if send_err is not None:
            raise send_err from None
        raise


def _upload_v1_multipart(path: Path, *, host: str, port: int, scheme: str, filename: str,
                         md5_hex: str, size: int, upload_token: Optional[str],
                         bearer_token: str, timeout: float, chunk_size: int,
                         progress: Optional[Callable[[int, int], None]]) -> Tuple[int, str]:
    boundary = f"----freewheel-{uuid.uuid4().hex}"
    head_parts = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"md5\"\r\n\r\n{md5_hex}\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"size\"\r\n\r\n{size}\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    footer = f"\r\n--{boundary}--\r\n".encode()

    conn = _make_connection(host, port, scheme, timeout)
    try:
        conn.putrequest("POST", "/upload")
        conn.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        conn.putheader("Content-Length", str(len(head_parts) + size + len(footer)))
        if bearer_token:
            conn.putheader("Authorization", f"Bearer {bearer_token}")
        if upload_token:
            conn.putheader("Upload-Token", upload_token)
        conn.endheaders()
        err: Optional[BaseException] = None
        try:
            conn.send(head_parts)
            sent = 0
            with path.open("rb") as fp:
                while chunk := fp.read(chunk_size):
                    conn.send(chunk)
                    sent += len(chunk)
                    if progress is not None:
                        progress(sent, size)
            conn.send(footer)
        except (BrokenPipeError, ConnectionResetError) as exc:
            err = exc
        return _read_response_after_stream(conn, err)
    finally:
        conn.close()


TUS_OFFSET_CONFLICT = (409, 460)


def _upload_v2_resumable(client: MdUpgradeClient, path: Path, *, upgrade_id: str,
                         upload_token: str, size: int, slice_size: int, timeout: float,
                         progress: Optional[Callable[[int, int], None]]) -> Tuple[int, str]:
    """Stream a package with TUS, continuing from whatever offset the robot acknowledges.

    A dropped link (or a re-used session from an earlier run) leaves bytes already
    accepted, so restarting at offset 0 would make the robot answer 409/460. We read the
    server offset, send only the missing slices, and retry a few conflicts before giving up.
    """
    offset = client.upload_offset(upgrade_id, upload_token, timeout=timeout)
    if offset is None:
        offset = 0
    last_status = 200
    conflicts = 0
    while offset < size:
        end = min(offset + slice_size, size)
        status = client.patch_slice(upgrade_id, upload_token, path, start=offset, end=end,
                                    file_size=size, io_chunk=min(slice_size, STREAM_CHUNK),
                                    timeout=timeout)
        last_status = status
        if status in TUS_OFFSET_CONFLICT:
            conflicts += 1
            if conflicts > 8:
                return status, f"TUS offset conflict persisted at offset {offset}"
            fresh = client.upload_offset(upgrade_id, upload_token, timeout=timeout)
            offset = fresh if fresh is not None else offset
            continue
        if status >= 400:
            return status, f"TUS PATCH failed at offset {offset} (HTTP {status})"
        conflicts = 0
        acknowledged = client.upload_offset(upgrade_id, upload_token, timeout=timeout)
        offset = acknowledged if acknowledged is not None else end
        if progress is not None:
            progress(min(offset, size), size)
    return last_status, ""


def upload_firmware(zip_path: str | Path, *, host: str = "192.168.7.1", port: int = DEFAULT_OTA_PORT,
                    ucp_port: int = DEFAULT_UCP_PORT, mode: str = "auto", scheme: str = "auto",
                    remote_filename: Optional[str] = None, bearer_token: Optional[str] = None,
                    device_id: Optional[str] = None, upgrade_id: Optional[str] = None,
                    upload_token: Optional[str] = None, verify_before_upload: bool = True,
                    base_zip_path: Optional[str | Path] = None,
                    allow_unsafe_x5_override: bool = False,
                    allow_mixed_firmware: bool = False,
                    allow_unsafe_mondo_pairing: bool = False,
                    min_battery_pct: int = MIN_SAFE_BATTERY_PCT, ignore_battery: bool = False,
                    max_retries: int = 2, timeout: float = 600.0, chunk_size: int = 4 * STREAM_CHUNK,
                    identity: Optional[str] = None,
                    progress: Optional[Callable[[int, int], None]] = None,
                    log: Optional[Callable[[str], None]] = None) -> UploadResult:
    """Validate and stream a package to `md_upgrade`, minting a live V2 grant when needed."""
    path = Path(zip_path)
    if not path.is_file():
        raise FileNotFoundError(f"firmware ZIP not found: {path}")
    if mode not in ("auto", "v1", "v2"):
        raise ValueError(f"mode must be auto|v1|v2, not {mode!r}")
    filename = remote_filename or path.name
    if not filename.startswith("V"):
        raise ValueError(f"md_upgrade requires the uploaded filename to start with 'V', got {filename!r}")

    warnings: List[str] = []
    if verify_before_upload:
        report = verify_package(path, base_zip_path=base_zip_path,
                                allow_unsafe_x5_override=allow_unsafe_x5_override,
                                allow_mixed_firmware=allow_mixed_firmware,
                                allow_unsafe_mondo_pairing=allow_unsafe_mondo_pairing,
                                logical_filename=filename)
        warnings.extend(report.warnings)

    # Whether the target commits a booted slot as successful without checking that /md
    # came up. When we cannot confirm the gate exists, say so loudly before flashing:
    # an ungated S99ota_update_check.sh (`ota_tool -b`) removes the A/B rollback entirely.
    gate_state = slot_commit_gating_from_base_zip(base_zip_path)
    banner = format_slot_commit_warning(gate_state)
    if banner:
        log and log(banner.strip("\n"))
        warnings.append(f"slot-commit gating is {gate_state.upper()} for this target")

    md5_hex, size = md5_file(path)
    sha = sha256_file(path)
    token = resolve_media_token(bearer_token)
    client = MdUpgradeClient(host, port, scheme=scheme, bearer_token=token)

    t0 = time.monotonic()
    active_mode = mode
    uid, grant = upgrade_id, upload_token

    # An explicit session (upgrade_id + Upload-Token) means the caller already minted a
    # V2 task; honour it in auto mode instead of silently doing a V1 multipart upload.
    if active_mode == "auto" and uid and grant:
        active_mode = "v2"

    if active_mode in ("auto", "v2") and not (uid and grant):
        uid, grant = None, None
        try:
            task = create_ota_task(path, host=host, ucp_port=ucp_port, device_id=device_id,
                                   min_battery_pct=min_battery_pct, ignore_battery=ignore_battery,
                                   identity=identity, log=log)
            uid, grant = task["upgrade_id"], task["upload_grant_token"]
            active_mode = "v2"
        except SafetyValidationError:
            # Never degrade an explicit safety refusal into a different upload protocol:
            # the V1 inbox path has no battery/posture gate of its own.
            raise
        except (MdUpgradeError, RuntimeError) as exc:
            if mode == "v2":
                raise
            warnings.append(f"V2 session unavailable ({exc}); falling back to the V1 inbox upload")
            active_mode = "v1"

    last_exc: Optional[BaseException] = None
    for attempt in range(max_retries + 1):
        try:
            if active_mode == "v2" and uid and grant:
                # Resume from the robot's acknowledged offset so an interrupted upload
                # (or a re-used session) continues instead of conflicting at offset 0.
                status, body = _upload_v2_resumable(
                    client, path, upgrade_id=uid, upload_token=grant, size=size,
                    slice_size=chunk_size, timeout=timeout, progress=progress,
                )
            else:
                status, body = _upload_v1_multipart(
                    path, host=host, port=port, scheme=client.scheme, filename=filename,
                    md5_hex=md5_hex, size=size, upload_token=grant, bearer_token=token,
                    timeout=timeout, chunk_size=chunk_size, progress=progress,
                )

            if status >= 500 and attempt < max_retries:
                time.sleep(1.0 * (attempt + 1))
                continue
            if status >= 400:
                hint = ""
                if status in (401, 403) and not token:
                    hint = (" (no media bearer configured — run "
                            "`python -m freewheel.ota extract-token <MondoApp.apk>`)")
                raise MdUpgradeError(f"upload failed with HTTP {status}{hint}: {body[:400]}")

            remote_verified = False
            if active_mode == "v2" and uid and grant:
                wait_task_ready(host, uid, grant, port=port, scheme=client.scheme, bearer_token=token,
                                timeout=min(timeout, 300.0))
                remote_verified = True
            else:
                listing = client.list_dir("")
                matched = [e for e in listing if e.name == filename or e.path.endswith("/" + filename)]
                if matched:
                    if matched[0].size >= 0 and matched[0].size != size:
                        raise SafetyValidationError(
                            f"/list size mismatch for {filename}: robot has {matched[0].size} bytes, "
                            f"we sent {size}"
                        )
                    remote_verified = True

            return UploadResult(
                mode=active_mode, scheme=client.scheme, host=host, port=port, filename=filename,
                size_bytes=size, md5=md5_hex, sha256=sha, status_code=status, response_body=body,
                elapsed_sec=time.monotonic() - t0, upgrade_id=uid, upload_token=grant,
                remote_verified=remote_verified, warnings=warnings,
            )
        except SafetyValidationError:
            raise
        except (OSError, http.client.HTTPException, MdUpgradeError) as exc:
            last_exc = exc
            if attempt < max_retries and not isinstance(exc, MdUpgradeError):
                time.sleep(1.0 * (attempt + 1))
                continue
            raise

    raise last_exc if last_exc else RuntimeError("upload failed")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _fmt_bytes(n: int) -> str:
    return f"{n / 1e6:.1f} MB" if n else "?"


def _bar(label: str) -> Callable[[int, int], None]:
    last = [0.0]

    def cb(done: int, total: int) -> None:
        now = time.monotonic()
        if now - last[0] < 0.2 and done != total:
            return
        last[0] = now
        pct = (done / total * 100) if total else 0.0
        print(f"\r  {label:<24} {pct:5.1f}%  {done / 1e6:7.1f}/{total / 1e6:7.1f} MB", end="", flush=True)

    return cb


def _doctor() -> int:
    print("freewheel doctor — what a self-contained jailbreak still needs\n")
    rows: List[Tuple[str, bool, str]] = []

    tok = resolve_media_token()
    if tok:
        rows.append(("media token", is_known_media_token(tok), "sha256 verified" if is_known_media_token(tok)
                     else "does NOT match the retail digest — re-extract it"))
    else:
        rows.append(("media token", False,
                     f"missing — python -m freewheel.ota extract-token <MondoApp.apk> (writes "
                     f"{default_media_token_path()})"))

    try:
        from . import ext4
        for tool in ("debugfs", "dumpe2fs", "e2fsck"):
            ext4.find_e2fs_tool(tool)
        rows.append(("e2fsprogs", True, "debugfs/dumpe2fs/e2fsck found"))
    except Exception as exc:  # noqa: BLE001
        rows.append(("e2fsprogs", False, str(exc)))

    try:
        import shutil
        rows.append(("ssh-keygen", bool(shutil.which("ssh-keygen")),
                     "found" if shutil.which("ssh-keygen") else "missing (needed for the SSH payload)"))
    except Exception:  # noqa: BLE001
        rows.append(("ssh-keygen", False, "missing"))

    from . import md_ts
    ident = Path(md_ts.default_identity_path())
    rows.append(("MD-TS identity", ident.is_file(),
                 str(ident) if ident.is_file() else
                 "missing — python -m freewheel.ble pair (needed for Zenoh /cmd on secure robots)"))

    base = Path("beni_fw/current_26.11/all_in_one.zip")
    rows.append(("base all_in_one.zip", base.is_file(),
                 str(base) if base.is_file() else
                 "missing — python -m freewheel.ota pull-firmware --host 192.168.7.1"))

    hbre = next(iter(sorted(Path("beni_fw").rglob("hbre.img"))), None) if Path("beni_fw").is_dir() else None
    hbre_detail = "missing — dump it off your robot: python -m freewheel.ota dump-partition hbre --host <IP>"
    if hbre is not None:
        size = hbre.stat().st_size
        hbre_detail = str(hbre)
        if size != HBRE_PARTITION_BYTES:
            hbre_detail = (f"{hbre} is {size:,} B, expected {HBRE_PARTITION_BYTES:,} — re-dump the "
                           "whole partition")
            hbre = None
    rows.append(("hbre.img", hbre is not None, hbre_detail))

    from . import partition_backup

    backup_root = partition_backup.DEFAULT_BACKUP_ROOT
    rows.extend(partition_backup.doctor_backup_rows(backup_root))

    ok_all = True
    for label, good, detail in rows:
        mark = "ok  " if good else "--  "
        print(f"  [{mark}] {label:<20} {detail}")
        ok_all &= good
    print()
    print("Ready for `python3 benibust.py --i-own-this-device`." if ok_all
          else "Resolve the '--' rows above, then re-run this doctor.")
    return 0 if ok_all else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m freewheel.ota",
        description="Owner firmware retrieval, package verification, and OTA upload — no external SDK.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Report which keys, firmware, and tools are still missing")

    p_tok = sub.add_parser("extract-token", help="Recover the media bearer from your own MondoApp.apk")
    p_tok.add_argument("source", help="MondoApp.apk, an APK/zip bundle, a .so/.dex, or a directory of them")
    p_tok.add_argument("--out", default=None, help=f"destination (default: {default_media_token_path()})")
    p_tok.add_argument("--expected-sha256", default=MEDIA_TOKEN_SHA256,
                       help="digest the robot compares against (default: the retail media digest)")
    p_tok.add_argument("--no-save", action="store_true", help="verify only; print the token, save nothing")
    p_tok.add_argument("--print", dest="echo", action="store_true", help="also print the recovered token")

    p_set = sub.add_parser("set-token", help="Save a token you captured yourself (verified, 0600)")
    p_set.add_argument("--out", default=None)
    p_set.add_argument("--expected-sha256", default=MEDIA_TOKEN_SHA256)
    p_set.add_argument("--value", default=None, help="token value (else read from stdin, unprompted)")

    p_show = sub.add_parser("show-token", help="Show where the token resolves from and whether it verifies")
    p_show.add_argument("--reveal", action="store_true", help="print the token itself")

    for name, hlp in (("inventory", "List firmware artifacts staged on the robot"),
                      ("status", "Query md_upgrade /health and /list")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("--host", default="192.168.7.1")
        p.add_argument("--port", type=int, default=DEFAULT_OTA_PORT)
        p.add_argument("--scheme", default="auto", choices=("auto", "http", "https"))
        p.add_argument("--bearer-token", default=None)
        p.add_argument("--json", action="store_true")

    p_pull = sub.add_parser("pull-firmware", help="Download all_in_one.zip / hbre.img off your robot")
    p_pull.add_argument("--host", default="192.168.7.1")
    p_pull.add_argument("--port", type=int, default=DEFAULT_OTA_PORT)
    p_pull.add_argument("--scheme", default="auto", choices=("auto", "http", "https"))
    p_pull.add_argument("--bearer-token", default=None)
    p_pull.add_argument("--out", default="beni_fw", help="output root (default: beni_fw)")
    p_pull.add_argument("--only", action="append", default=None,
                        help="restrict to an artifact name (repeatable, e.g. --only hbre.img)")
    p_pull.add_argument("--json", action="store_true")

    p_tree = sub.add_parser(
        "pull-workdir",
        help="Enumerate md_upgrade's work dir and grab EVERYTHING (the original capture method)",
    )
    p_tree.add_argument("--host", default="192.168.7.1")
    p_tree.add_argument("--port", type=int, default=DEFAULT_OTA_PORT)
    p_tree.add_argument("--scheme", default="auto", choices=("auto", "http", "https"))
    p_tree.add_argument("--bearer-token", default=None)
    p_tree.add_argument("--out", default="beni_fw/dump", help="output dir (default: beni_fw/dump)")
    p_tree.add_argument("--start", default="", help="subdirectory to grab (default: the whole work dir)")
    p_tree.add_argument("--max-depth", type=int, default=4)
    p_tree.add_argument("--json", action="store_true")

    p_dump = sub.add_parser(
        "dump-partition",
        help="Read a partition straight off a rooted robot over SSH (the exact image)",
    )
    p_dump.add_argument("partition", nargs="?", default="hbre",
                        help="partition name, e.g. hbre, system, mondo (default: hbre)")
    p_dump.add_argument("--host", required=True, help="robot IP")
    p_dump.add_argument("--ssh-port", type=int, default=2222)
    p_dump.add_argument("--ssh-key", default=None, help="private key (default: ~/.ssh/freewheel_ed25519)")
    p_dump.add_argument("--slot", choices=("current", "a", "b"), default="current",
                        help="'current' follows by-name/<part>; 'a'/'b' pin an explicit slot")
    p_dump.add_argument("--out", default=None, help="destination (default: beni_fw/dump/<part>.img)")
    p_dump.add_argument("--size", type=int, default=None,
                        help="expected byte count; defaults to the known partition size")
    p_dump.add_argument("--json", action="store_true")

    p_restore = sub.add_parser(
        "restore-backup",
        help="Write mondo/misc (and optional hbre slot) images back from a rollback manifest",
    )
    p_restore.add_argument("backup_dir", help="directory containing rollback-manifest.txt")
    p_restore.add_argument("--host", required=True, help="robot IP (root SSH)")
    p_restore.add_argument("--ssh-port", type=int, default=2222)
    p_restore.add_argument("--ssh-key", default=None)
    p_restore.add_argument("--dry-run", action="store_true", help="print the restore plan only")
    p_restore.add_argument("--json", action="store_true")

    p_ver = sub.add_parser("verify", help="Structurally verify an OTA package before flashing")
    p_ver.add_argument("package")
    p_ver.add_argument("--base", default=None, help="the stock all_in_one.zip the package was built from")
    p_ver.add_argument("--allow-unsafe-x5-override", action="store_true")
    p_ver.add_argument("--allow-mixed-firmware", action="store_true",
                       help="permit a package whose modules come from different firmware builds")
    p_ver.add_argument("--allow-unsafe-mondo-pairing", action="store_true",
                       help="permit a shared_blocks mondo.img under a read-write-mounting system.img")

    p_up = sub.add_parser("upload", help="Upload (and optionally install) a package")
    p_up.add_argument("package")
    p_up.add_argument("--host", default="192.168.7.1")
    p_up.add_argument("--port", type=int, default=DEFAULT_OTA_PORT)
    p_up.add_argument("--ucp-port", type=int, default=DEFAULT_UCP_PORT)
    p_up.add_argument("--scheme", default="auto", choices=("auto", "http", "https"))
    p_up.add_argument("--mode", default="auto", choices=("auto", "v1", "v2"))
    p_up.add_argument("--bearer-token", default=None)
    p_up.add_argument("--device-id", default=None, help="robot serial (auto-queried when omitted)")
    p_up.add_argument("--identity", default=None)
    p_up.add_argument("--base", default=None)
    p_up.add_argument("--allow-mixed-firmware", action="store_true",
                      help="permit uploading a package whose modules come from different builds")
    p_up.add_argument("--allow-unsafe-mondo-pairing", action="store_true",
                      help="permit uploading a shared_blocks mondo.img under a rw-mounting system.img")
    p_up.add_argument("--no-verify", action="store_true", help="skip the pre-upload package validation")
    p_up.add_argument("--ignore-battery", action="store_true")
    p_up.add_argument("--install", action="store_true", help="trigger the install once the robot says READY")
    p_up.add_argument("--check-posture", action="store_true", help="also refuse if the robot is standing")

    args = ap.parse_args(argv)

    try:
        if args.cmd == "doctor":
            return _doctor()

        if args.cmd == "extract-token":
            token = extract_media_token_from_apk(
                args.source, save=not args.no_save, save_path=Path(args.out) if args.out else None,
                expected_sha256=args.expected_sha256, progress=lambda m: print(f"  [*] {m}"),
            )
            print(f"  [+] media token recovered and verified against sha256 {args.expected_sha256[:16]}…")
            if args.echo:
                print(f"      {token}")
            if not args.no_save:
                print(f"      saved to {Path(args.out) if args.out else default_media_token_path()} (0600)")
            return 0

        if args.cmd == "set-token":
            value = args.value if args.value is not None else sys.stdin.readline().strip()
            if not value:
                value = getpass.getpass("media bearer token: ").strip()
            target = save_media_token(value, Path(args.out) if args.out else None,
                                      expected_sha256=args.expected_sha256)
            print(f"  [+] verified and saved {target} (0600)")
            return 0

        if args.cmd == "show-token":
            token = resolve_media_token()
            if not token:
                print("  [!] no token configured")
                print(f"      run: python -m freewheel.ota extract-token <MondoApp.apk>")
                return 1
            good = is_known_media_token(token)
            print(f"  [{'ok' if good else '!!'}] resolved {'a' if good else 'an INVALID'} token "
                  f"({'matches' if good else 'does not match'} the retail digest)")
            print("      sources checked: " + ", ".join(f"${v}" for v in TOKEN_ENV_VARS)
                  + f", {default_media_token_path()}, {legacy_media_token_path()}")
            if args.reveal:
                print(f"      {token}")
            return 0 if good else 1

        if args.cmd in ("inventory", "status"):
            client = MdUpgradeClient(args.host, args.port, scheme=args.scheme, bearer_token=args.bearer_token)
            if args.cmd == "status":
                payload = check_robot_ota(args.host, args.port, scheme=client.scheme,
                                          bearer_token=args.bearer_token)
            else:
                payload = client.firmware_inventory()
            if args.json:
                print(json.dumps(payload, indent=2))
                return 0

            if args.cmd == "status":
                print(f"== md_upgrade {client.scheme}://{args.host}:{args.port} ==")
                print(f"  health:   {payload.get('health')}")
                print(f"  packages: {payload.get('packages')}")
                return 0

            print(f"== firmware staged on {args.host} (:8085 {client.scheme}) ==")
            if not payload["artifacts"]:
                print("  (nothing found — this robot's md_upgrade work dir has been cleaned)")
                print("  Fallbacks: capture an update with `python -m freewheel.fwextract`, or read")
                print("  the partition directly once rooted (`dd if=/dev/block/platform/by-name/hbre`).")
                return 1
            for a in payload["artifacts"]:
                print(f"  {a['size'] / 1e6:9.1f} MB  {a['path']}")
            return 0

        if args.cmd == "pull-firmware":
            def _p(name: str, done: int, total: int) -> None:
                cb = _bar(name)
                cb(done, total)

            res = pull_robot_firmware(
                args.host, out_dir=args.out, port=args.port, scheme=args.scheme,
                bearer_token=args.bearer_token, only=args.only, progress=_p,
            )
            print()
            if args.json:
                print(json.dumps({k: v for k, v in res.items() if k != "inventory"}, indent=2))
            for item in res["downloaded"]:
                verb = "have" if item["skipped"] else "pulled"
                print(f"  [+] {verb} {item['name']} -> {item['path']} ({_fmt_bytes(item['size'])})")
            if res["missing"]:
                print(f"  [!] not staged on this unit: {', '.join(res['missing'])}")
                print("      md_upgrade keeps the outer archive under tmp/ only until the next OTA;")
                print("      if it is gone, capture an app update with `python -m freewheel.fwextract`.")
            return 0 if res["downloaded"] else 1

        if args.cmd == "pull-workdir":
            def _pt(name: str, done: int, total: int) -> None:
                _bar(Path(name).name)(done, total)

            res = pull_work_tree(
                args.host, out_dir=args.out, port=args.port, scheme=args.scheme,
                bearer_token=args.bearer_token, start=args.start,
                max_depth=args.max_depth, progress=_pt,
            )
            print()
            if args.json:
                print(json.dumps(res, indent=2))
            for item in res["files"]:
                verb = "have" if item["skipped"] else "pulled"
                print(f"  [+] {verb} {item['path']} -> {item['local']} ({_fmt_bytes(item['size'])})")
            for failure in res["failures"]:
                print(f"  [!] {failure['path']}: {failure['error']}")
            print(f"      {len(res['files'])} file(s), {_fmt_bytes(res['total_bytes'])} into {res['out_dir']}")
            return 0 if res["files"] and not res["failures"] else 1

        if args.cmd == "dump-partition":
            try:
                res = dump_partition(
                    args.partition, host=args.host, ssh_port=args.ssh_port,
                    ssh_key=args.ssh_key, slot=args.slot, out=args.out,
                    expected_size=args.size, progress=_bar(args.partition),
                )
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
                print(f"\n  [x] {exc}", file=sys.stderr)
                return 1
            print()
            if args.json:
                print(json.dumps(res, indent=2))
            print(f"  [+] {res['partition']} ({res['slot']} slot) -> {res['local']}")
            print(f"      {res['bytes']:,} bytes  sha256 {res['sha256']}")
            print(f"      remote node: {res['node']} -> {res['resolved']}")
            for note in res["notes"]:
                print(f"  [!] {note}")
            if not res["ok"]:
                print("      A short read is rejected on-device; fix the cause and re-dump.")
            return 0 if res["ok"] else 1

        if args.cmd == "restore-backup":
            from . import partition_backup

            backup_dir = Path(args.backup_dir)
            manifest = partition_backup.load_manifest(backup_dir)
            if manifest is None:
                print(f"  [x] no {partition_backup.ROLLBACK_MANIFEST} in {backup_dir}", file=sys.stderr)
                return 1
            plan = partition_backup.describe_restore_plan(manifest, backup_dir)
            print(plan)
            if args.dry_run:
                return 0
            try:
                results = partition_backup.execute_restore(
                    args.host,
                    backup_dir,
                    ssh_port=args.ssh_port,
                    ssh_key=args.ssh_key,
                    progress=lambda label, done, total: _bar(label)(done, total),
                )
            except partition_backup.PartitionBackupError as exc:
                print(f"\n  [x] {exc}", file=sys.stderr)
                return 1
            print()
            if args.json:
                print(json.dumps(results, indent=2))
            for item in results:
                print(f"  [+] restored {item['partition']} ({item['slot']}) -> {item['node']}")
                print(f"      {item['bytes']:,} bytes  sha256 {item['sha256']}")
            print("  Reboot and verify /proc/cmdline hobotboot.slot_suffix before trusting the slot.")
            return 0

        if args.cmd == "verify":
            report = verify_package(args.package, base_zip_path=args.base,
                                    allow_unsafe_x5_override=args.allow_unsafe_x5_override,
                                    allow_mixed_firmware=args.allow_mixed_firmware,
                                    allow_unsafe_mondo_pairing=args.allow_unsafe_mondo_pairing)
            print(f"  [+] {report.zip_path.name}: V{report.package_version}")
            print(f"      manifest: {report.manifest_name}")
            print(f"      modules verified: {report.verified_modules}")
            print(f"      0300 partitions verified: {report.verified_x5_partitions}")
            if report.ota_process_mode is not None:
                print(f"      ota_process mode: {oct(report.ota_process_mode)}")
            for w in report.warnings:
                print(f"  [!] {w}")
            gate = slot_commit_gating_from_base_zip(args.base)
            print(f"      slot-commit gating: {gate.upper()}"
                  + ("" if gate == "gated" else
                     " (pass --base <stock all_in_one.zip> to determine this)" if gate == "unknown" else ""))
            banner = format_slot_commit_warning(gate)
            if banner:
                print(banner, file=sys.stderr)
            return 0

        if args.cmd == "upload":
            result = upload_firmware(
                args.package, host=args.host, port=args.port, ucp_port=args.ucp_port, mode=args.mode,
                scheme=args.scheme, bearer_token=args.bearer_token, device_id=args.device_id,
                identity=args.identity, base_zip_path=args.base,
                allow_mixed_firmware=args.allow_mixed_firmware,
                allow_unsafe_mondo_pairing=args.allow_unsafe_mondo_pairing,
                verify_before_upload=not args.no_verify, ignore_battery=args.ignore_battery,
                progress=_bar(Path(args.package).name), log=lambda m: print(f"  [*] {m}"),
            )
            print()
            print(f"  [+] uploaded ({result.mode}) in {result.elapsed_sec:.0f}s — "
                  f"upgrade_id={result.upgrade_id} verified={result.remote_verified}")
            for w in result.warnings:
                print(f"  [!] {w}")
            if args.install:
                res = trigger_ota_install(
                    args.host, upgrade_id=result.upgrade_id or "", upload_token=result.upload_token or "",
                    port=args.port, scheme=args.scheme, bearer_token=args.bearer_token,
                    check_posture=args.check_posture, ignore_battery=args.ignore_battery,
                    identity=args.identity, log=lambda m: print(f"  [*] {m}"),
                )
                print(f"  [+] install triggered via {res.get('method')} — the robot will reboot")
            return 0

        ap.error(f"unknown command {args.cmd}")
        return 2
    except SafetyValidationError as exc:
        print(f"\n  [x] safety check failed: {exc}", file=sys.stderr)
        return 2
    except (MdUpgradeError, FileNotFoundError, LookupError, ConnectionError, TimeoutError) as exc:
        print(f"\n  [x] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
