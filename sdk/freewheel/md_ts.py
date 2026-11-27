"""MD-TS (`secure_v2`) encrypted control-bus session over zenoh.

Clean-room implementation of the byte-level spec in
native-analysis/community-crosscheck.md §4 (a community cross-check that first
published the layout, and which reports hardware testing on an LZ110). Known-answer
vectors frozen from that cross-check are checked in tests/test_md_ts.py.

Summary:
  * Both sides hold static X25519 keys. The robot only accepts client keys it
    authorized during a Bluetooth pairing with a 3-5 s button hold (`freewheel.ble`
    pairs over GATT `0000FFF0` and writes `~/.config/freewheel/identity.json`).
  * BLE handshake (`0x55` <-> `0x56`, `transport = 1`):
      C->S  1 CLIENT_HELLO       hdr + client_static_pub[32]         (flags=0x00)
      S->C  3 PENDING_BUTTON     hdr + status_u8                     (0x01=hold button, 0x03=busy)
      S->C  2 SERVER_HELLO       hdr + robot_static_pub[32]          (flags=0x00)
      then 4 -> 5 -> 6 -> 7 below with 35-byte BLE AAD.
  * Zenoh handshake on `app/security/session` <-> `device/security/session` (`transport = 2`):
      C->S  4 SESSION_START      hdr + client_nonce[32]              (plaintext, envelope field 5)
      S->C  5 SESSION_CHALLENGE  hdr + server_nonce[32] + channel_id[8]
      C->S  6 CLIENT_CONFIRM     hdr + transcript_hash, sealed at seq 0 (envelope fields 3=1, 4)
      S->C  7 SERVER_CONFIRM     hdr + transcript_hash, sealed at seq 0
      S->C  0x7F ERROR           hdr + u16 BE error code
    hdr = 01 01 | msg_type | client_id[16] | key_version u32 BE   (23 bytes)
  * transcript = SHA-256("MD-TS-HS\\0" 01 01 transport | client_id | key_version |
    client_pub | robot_pub | client_nonce | server_nonce | channel_id)   (168-byte preimage)
  * key[dir] = HKDF-SHA256(ikm=X25519(static, static), salt=SHA-256(cnonce||snonce),
    info="MD-TS-KEY\\0" 01 01 | transport | dir | transcript, 32 bytes); dir 0 = C->S.
  * AEAD AES-256-GCM, IV = 00*8 || u32 BE seq, AAD = "MD-TS-AAD\\0" 01 01 02 | dir | 01 |
    channel_id | u64 BE seq | u16 len | keyexpr | u16 len | encoding.
    Record = channel_id || u64 BE seq || ciphertext || tag. Application seq >= 1,
    1024-entry anti-replay window.
  * Envelope (protobuf `MdTsZenohEnvelope`): handshake `2A len hs`; sealed `18 01 22 len record`.
    A normal plaintext message starts with field 1 or 2 and is not an envelope.

`cryptography` is required for X25519/AES-GCM and is imported lazily, so the
plaintext SDK stays dependency-free.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
from dataclasses import dataclass
from typing import Callable, Optional

VERSION = b"\x01\x01"

# Pre-1.0 config location/env var, still honoured so an existing pairing keeps working.
_LEGACY_CONFIG_DIR = "pynebi"
_LEGACY_IDENTITY_ENV = "PYNEBI_IDENTITY_PATH"

TRANSPORT_BLE = 1
TRANSPORT_ZENOH = 2
DIR_C2S = 0
DIR_S2C = 1
ROLE_CLIENT = 0
ROLE_SERVER = 1

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_PENDING_BUTTON = 3
HS_SESSION_START = 4
HS_SESSION_CHALLENGE = 5
HS_CLIENT_CONFIRM = 6
HS_SERVER_CONFIRM = 7
HS_ERROR = 0x7F
HS_HEADER_LEN = 23
BLE_MAX_PLAINTEXT = 218       # 255 max V0 BLE frame - (4B hdr + 32B record + 1B CRC8)
_BLE_SOF = 0x55
_BLE_FLAG_MD_TS = 0x04
_BLE_CMD_CLIENT = 0x55
_BLE_CMD_SERVER = 0x56
_BLE_FRAME_OVERHEAD = 5       # 4B header + 1B CRC8

ERR_UNAUTHORIZED = 0x0003
ERR_PUBKEY_MISMATCH = 0x0004
ERR_SESSION_BUSY = 0x0005
ERR_INTERNAL = 0x0007
ERR_PENDING_NOT_FINALIZED = 0x0008
ERR_TIMEOUT = 0x0009
ERR_AUTH_TABLE_FULL = 0x000A
ERROR_NAMES = {
    ERR_UNAUTHORIZED: "UNAUTHORIZED_CLIENT",
    ERR_PUBKEY_MISMATCH: "PUBLIC_KEY_MISMATCH",
    ERR_SESSION_BUSY: "HANDSHAKE_SESSION_BUSY",
    ERR_INTERNAL: "INTERNAL_SECURITY_ERROR",
    ERR_PENDING_NOT_FINALIZED: "BUTTON_AUTH_NOT_FINALIZED",
    ERR_TIMEOUT: "HANDSHAKE_TIMEOUT",
    ERR_AUTH_TABLE_FULL: "AUTHORIZATION_TABLE_FULL",
}

APP_SECURITY_KEYEXPR = "app/security/session"
DEVICE_SECURITY_KEYEXPR = "device/security/session"
SECURITY_TOPIC = "security/session"
DEFAULT_ENCODING = "application/protobuf"
RECORD_OVERHEAD = 32           # channel_id 8 + seq 8 + GCM tag 16
REPLAY_WINDOW = 1024

PAIRING_HINT = ("pair this client with the robot once over Bluetooth (`python -m freewheel.ble pair` "
                "or the web console's BLE Pair button, holding the robot's button 3-5 s)")


class MdTsError(Exception):
    """A handshake or record failure. `code` is a short machine name."""

    def __init__(self, code: str, message: str, hint: str = ""):
        super().__init__(f"{code}: {message}" + (f" ({hint})" if hint else ""))
        self.code = code
        self.hint = hint


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
    except ImportError as e:  # pragma: no cover - environment dependent
        raise MdTsError("CRYPTO_UNAVAILABLE", "MD-TS needs the `cryptography` package",
                        "pip install cryptography") from e
    return serialization, X25519PrivateKey, X25519PublicKey, AESGCM, InvalidTag


def _nonzero(b: bytes, n: int, what: str) -> bytes:
    b = bytes(b)
    if len(b) != n or not any(b):
        raise ValueError(f"{what} must be {n} non-zero bytes")
    return b


def random_nonzero(n: int) -> bytes:
    while True:
        b = secrets.token_bytes(n)
        if any(b):
            return b


# ── X25519 / KDF ─────────────────────────────────────────────────────────────
def x25519_public(private_key: bytes) -> bytes:
    ser, Priv, _, _, _ = _crypto()
    return Priv.from_private_bytes(_nonzero(private_key, 32, "private key")).public_key().public_bytes(
        ser.Encoding.Raw, ser.PublicFormat.Raw)


def x25519(private_key: bytes, peer_public: bytes) -> bytes:
    _, Priv, Pub, _, _ = _crypto()
    shared = Priv.from_private_bytes(_nonzero(private_key, 32, "private key")).exchange(
        Pub.from_public_bytes(_nonzero(peer_public, 32, "peer public key")))
    if not any(shared):
        raise MdTsError("BAD_SHARED_SECRET", "all-zero X25519 shared secret")
    return shared


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def transcript_hash(*, transport: int, client_id: bytes, key_version: int, client_pub: bytes,
                    robot_pub: bytes, client_nonce: bytes, server_nonce: bytes,
                    channel_id: bytes) -> bytes:
    pre = (b"MD-TS-HS\x00" + VERSION + bytes([transport]) + _nonzero(client_id, 16, "client_id")
           + struct.pack(">I", key_version) + _nonzero(client_pub, 32, "client_pub")
           + _nonzero(robot_pub, 32, "robot_pub") + _nonzero(client_nonce, 32, "client_nonce")
           + _nonzero(server_nonce, 32, "server_nonce") + _nonzero(channel_id, 8, "channel_id"))
    assert len(pre) == 168
    return hashlib.sha256(pre).digest()


def derive_keys(shared_secret: bytes, client_nonce: bytes, server_nonce: bytes, transport: int,
                th: bytes) -> tuple:
    """(key_c2s, key_s2c)."""
    salt = hashlib.sha256(client_nonce + server_nonce).digest()
    return tuple(hkdf_sha256(shared_secret, salt, b"MD-TS-KEY\x00" + VERSION + bytes([transport, d]) + th)
                 for d in (DIR_C2S, DIR_S2C))


def zenoh_aad(direction: int, channel_id: bytes, seq: int, keyexpr: str,
              encoding: str = DEFAULT_ENCODING) -> bytes:
    ke, enc = keyexpr.lstrip("/").encode("ascii"), encoding.encode("ascii")
    return (b"MD-TS-AAD\x00" + VERSION + bytes([TRANSPORT_ZENOH, direction & 0xFF, 1]) + bytes(channel_id)
            + struct.pack(">Q", seq) + struct.pack(">H", len(ke)) + ke + struct.pack(">H", len(enc)) + enc)


def ble_aad(direction: int, channel_id: bytes, seq: int, ble_hdr: bytes) -> bytes:
    """Exact 35-byte (`0x23`) BLE AAD over `ble_hdr` (`[0x55, total_len, flags, cmd_id]`)."""
    if len(ble_hdr) != 4:
        raise ValueError("ble_hdr must be 4 bytes")
    aad = (b"MD-TS-AAD\x00" + VERSION + bytes([TRANSPORT_BLE, direction & 0xFF, 1])
           + _nonzero(channel_id, 8, "channel_id") + struct.pack(">Q", seq) + bytes(ble_hdr))
    assert len(aad) == 35
    return aad


# ── envelope + handshake messages ────────────────────────────────────────────
def _varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _rd_varint(b: bytes, i: int):
    v = shift = 0
    while i < len(b):
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not c & 0x80:
            return v, i
        shift += 7
        if shift > 63:
            break
    raise ValueError("bad varint")


def encode_hs_envelope(hs: bytes) -> bytes:
    return b"\x2a" + _varint(len(hs)) + bytes(hs)


def encode_enc_envelope(record: bytes) -> bytes:
    return b"\x18\x01\x22" + _varint(len(record)) + bytes(record)


def decode_envelope(raw: bytes):
    """("handshake", hs) | ("encrypted", record) | None for a normal plaintext message."""
    raw = bytes(raw)
    if not raw:
        return None
    i, mode, rec, hs, seen = 0, 0, None, None, False
    try:
        while i < len(raw):
            tag, i = _rd_varint(raw, i)
            field, wt = tag >> 3, tag & 7
            if field in (1, 2):
                return None                       # WireHeader / Data: ordinary message
            if field == 3 and wt == 0:
                mode, i = _rd_varint(raw, i)
            elif field in (4, 5) and wt == 2:
                n, i = _rd_varint(raw, i)
                if i + n > len(raw):
                    return None
                if field == 4:
                    rec = raw[i:i + n]
                else:
                    hs = raw[i:i + n]
                i += n
            else:
                return None
            seen = True
    except ValueError:
        return None
    if not seen:
        return None
    if mode == 1 and rec:
        return ("encrypted", rec)
    if mode == 0 and hs:
        return ("handshake", hs)
    return None


def hs_header(msg_type: int, client_id: bytes, key_version: int) -> bytes:
    if not 0 < key_version <= 0xFFFFFFFF:
        raise ValueError("bad key_version")
    return VERSION + bytes([msg_type]) + _nonzero(client_id, 16, "client_id") + struct.pack(">I", key_version)


@dataclass(frozen=True)
class HsMessage:
    msg_type: int
    client_id: bytes
    key_version: int
    public_key: bytes = b""
    pending_status: int = 0
    nonce: bytes = b""
    channel_id: bytes = b""
    transcript_hash: bytes = b""
    error_code: int = 0

    @property
    def error_name(self) -> str:
        return ERROR_NAMES.get(self.error_code, f"ERR_0x{self.error_code:04X}")


def parse_hs(raw: bytes) -> HsMessage:
    d = bytes(raw)
    if len(d) < HS_HEADER_LEN or d[:2] != VERSION:
        raise ValueError("not an MD-TS-HS message")
    t, cid, (kv,) = d[2], d[3:19], struct.unpack_from(">I", d, 19)
    if not any(cid) or kv == 0:
        raise ValueError("zero client_id / key_version")
    body = d[23:]
    if t in (HS_CLIENT_HELLO, HS_SERVER_HELLO) and len(body) == 32 and any(body):
        return HsMessage(t, cid, kv, public_key=body)
    if t == HS_PENDING_BUTTON and len(body) == 1:
        return HsMessage(t, cid, kv, pending_status=body[0])
    if t == HS_SESSION_START and len(body) == 32 and any(body):
        return HsMessage(t, cid, kv, nonce=body)
    if t == HS_SESSION_CHALLENGE and len(body) == 40 and any(body[:32]) and any(body[32:]):
        return HsMessage(t, cid, kv, nonce=body[:32], channel_id=body[32:])
    if t in (HS_CLIENT_CONFIRM, HS_SERVER_CONFIRM) and len(body) == 32 and any(body):
        return HsMessage(t, cid, kv, transcript_hash=body)
    if t == HS_ERROR and len(body) == 2:
        return HsMessage(t, cid, kv, error_code=struct.unpack(">H", body)[0])
    raise ValueError(f"unsupported MD-TS-HS msg_type 0x{t:02X} / length {len(body)}")


def build_client_hello(client_id: bytes, key_version: int, client_pub: bytes) -> bytes:
    return hs_header(HS_CLIENT_HELLO, client_id, key_version) + _nonzero(client_pub, 32, "client_pub")


def build_server_hello(client_id: bytes, key_version: int, robot_pub: bytes) -> bytes:
    return hs_header(HS_SERVER_HELLO, client_id, key_version) + _nonzero(robot_pub, 32, "robot_pub")


def build_pending_button(client_id: bytes, key_version: int, status: int = 0x01) -> bytes:
    return hs_header(HS_PENDING_BUTTON, client_id, key_version) + bytes([status & 0xFF])


def build_session_start(client_id: bytes, key_version: int, client_nonce: bytes) -> bytes:
    return hs_header(HS_SESSION_START, client_id, key_version) + _nonzero(client_nonce, 32, "client_nonce")


def build_session_challenge(client_id: bytes, key_version: int, server_nonce: bytes, channel_id: bytes) -> bytes:
    return (hs_header(HS_SESSION_CHALLENGE, client_id, key_version) + _nonzero(server_nonce, 32, "server_nonce")
            + _nonzero(channel_id, 8, "channel_id"))


def build_error(client_id: bytes, key_version: int, code: int) -> bytes:
    return hs_header(HS_ERROR, client_id, key_version) + struct.pack(">H", code)


# ── session (AEAD + replay window) ───────────────────────────────────────────
class Session:
    """An established (or confirming) MD-TS channel (Zenoh or BLE). Thread-safe."""

    def __init__(self, role: int, channel_id: bytes, transcript: bytes, key_c2s: bytes, key_s2c: bytes,
                 *, transport: int = TRANSPORT_ZENOH):
        _, _, _, AESGCM, self._InvalidTag = _crypto()
        self.role = role
        self.transport = transport
        self.channel_id = _nonzero(channel_id, 8, "channel_id")
        self.transcript_hash = _nonzero(transcript, 32, "transcript_hash")
        tx, rx = (key_c2s, key_s2c) if role == ROLE_CLIENT else (key_s2c, key_c2s)
        self.tx_dir = DIR_C2S if role == ROLE_CLIENT else DIR_S2C
        self.rx_dir = 1 - self.tx_dir
        self._tx, self._rx = AESGCM(tx), AESGCM(rx)
        self.tx_seq = 1
        self._rx_max = 0
        self._rx_bits = 0
        self.confirmed = False
        self._lock = threading.Lock()

    @classmethod
    def from_handshake(cls, *, role: int, transport: int, private_key: bytes, peer_public_key: bytes,
                       client_id: bytes, key_version: int, client_pub: bytes, robot_pub: bytes,
                       client_nonce: bytes, server_nonce: bytes, channel_id: bytes) -> "Session":
        th = transcript_hash(transport=transport, client_id=client_id, key_version=key_version,
                             client_pub=client_pub, robot_pub=robot_pub,
                             client_nonce=client_nonce, server_nonce=server_nonce, channel_id=channel_id)
        kc, ks = derive_keys(x25519(private_key, peer_public_key), client_nonce, server_nonce, transport, th)
        return cls(role, channel_id, th, kc, ks, transport=transport)

    @staticmethod
    def _iv(seq: int) -> bytes:
        if not 0 <= seq <= 0xFFFFFFFF:
            raise ValueError("seq exceeds the 32-bit IV")
        return b"\x00" * 8 + struct.pack(">I", seq)

    def _record(self, seq: int, ct: bytes) -> bytes:
        return self.channel_id + struct.pack(">Q", seq) + ct

    def _split(self, record: bytes):
        rec = bytes(record)
        if len(rec) < RECORD_OVERHEAD:
            raise MdTsError("BAD_RECORD", f"truncated record ({len(rec)} B)")
        if rec[:8] != self.channel_id:
            raise MdTsError("BAD_RECORD", "channel_id mismatch")
        return struct.unpack_from(">Q", rec, 8)[0], rec[16:]

    # handshake confirms (seq 0)
    def seal_confirm(self, client_id: bytes, key_version: int, keyexpr: str) -> bytes:
        t = HS_CLIENT_CONFIRM if self.role == ROLE_CLIENT else HS_SERVER_CONFIRM
        pt = hs_header(t, client_id, key_version) + self.transcript_hash
        return self._record(0, self._tx.encrypt(self._iv(0), pt, zenoh_aad(self.tx_dir, self.channel_id, 0, keyexpr)))

    def open_confirm(self, record: bytes, client_id: bytes, key_version: int, keyexpr: str) -> None:
        seq, ct = self._split(record)
        if seq != 0:
            raise MdTsError("BAD_CONFIRM", f"confirm must use seq 0, got {seq}")
        try:
            pt = self._rx.decrypt(self._iv(0), ct, zenoh_aad(self.rx_dir, self.channel_id, 0, keyexpr))
        except self._InvalidTag as e:
            raise MdTsError("BAD_CONFIRM", "confirm failed authentication") from e
        want = HS_SERVER_CONFIRM if self.role == ROLE_CLIENT else HS_CLIENT_CONFIRM
        if pt != hs_header(want, client_id, key_version) + self.transcript_hash:
            raise MdTsError("BAD_CONFIRM", "confirm transcript mismatch")
        self.confirmed = True

    def seal_ble_confirm(self, client_id: bytes, key_version: int,
                         ble_cmd_id: Optional[int] = None) -> bytes:
        t = HS_CLIENT_CONFIRM if self.role == ROLE_CLIENT else HS_SERVER_CONFIRM
        pt = hs_header(t, client_id, key_version) + self.transcript_hash
        cmd = ble_cmd_id if ble_cmd_id is not None else (
            _BLE_CMD_CLIENT if self.role == ROLE_CLIENT else _BLE_CMD_SERVER
        )
        total_len = _BLE_FRAME_OVERHEAD + RECORD_OVERHEAD + len(pt)
        hdr = bytes([_BLE_SOF, total_len & 0xFF, _BLE_FLAG_MD_TS, cmd & 0xFF])
        return self._record(0, self._tx.encrypt(self._iv(0), pt, ble_aad(self.tx_dir, self.channel_id, 0, hdr)))

    def open_ble_confirm(self, record: bytes, client_id: bytes, key_version: int,
                         ble_hdr: Optional[bytes] = None) -> None:
        seq, ct = self._split(record)
        if seq != 0:
            raise MdTsError("BAD_CONFIRM", f"confirm must use seq 0, got {seq}")
        if ble_hdr is None:
            cmd = _BLE_CMD_SERVER if self.role == ROLE_CLIENT else _BLE_CMD_CLIENT
            ble_hdr = bytes([_BLE_SOF, (_BLE_FRAME_OVERHEAD + len(record)) & 0xFF, _BLE_FLAG_MD_TS, cmd])
        try:
            pt = self._rx.decrypt(self._iv(0), ct, ble_aad(self.rx_dir, self.channel_id, 0, ble_hdr))
        except self._InvalidTag as e:
            raise MdTsError("BAD_CONFIRM", "BLE confirm failed authentication") from e
        want = HS_SERVER_CONFIRM if self.role == ROLE_CLIENT else HS_CLIENT_CONFIRM
        if pt != hs_header(want, client_id, key_version) + self.transcript_hash:
            raise MdTsError("BAD_CONFIRM", "BLE confirm transcript mismatch")
        self.confirmed = True

    # application payloads (seq >= 1)
    def seal_ble(self, cmd_id: int, plaintext: bytes) -> bytes:
        """Encrypt a V0 BLE application payload (`seq >= 1`); returns the raw AEAD record."""
        pt = bytes(plaintext)
        if len(pt) > BLE_MAX_PLAINTEXT:
            raise MdTsError("PAYLOAD_TOO_LARGE", f"BLE plaintext {len(pt)} B > {BLE_MAX_PLAINTEXT}")
        with self._lock:
            seq = self.tx_seq
            if seq > 0xFFFFFFFF:
                raise MdTsError("SEQ_EXHAUSTED", "TX sequence space exhausted; renegotiate")
            self.tx_seq += 1
        total_len = _BLE_FRAME_OVERHEAD + RECORD_OVERHEAD + len(pt)
        hdr = bytes([_BLE_SOF, total_len & 0xFF, _BLE_FLAG_MD_TS, cmd_id & 0xFF])
        ct = self._tx.encrypt(self._iv(seq), pt, ble_aad(self.tx_dir, self.channel_id, seq, hdr))
        return self._record(seq, ct)

    def open_ble(self, cmd_id: int, flags: int, record: bytes, *, check_replay: bool = True) -> bytes:
        """Authenticate + decrypt a `flags=0x04` BLE application record (`seq >= 1`)."""
        seq, ct = self._split(record)
        if seq == 0 or seq > 0xFFFFFFFF:
            raise MdTsError("BAD_SEQ", f"application seq out of range: {seq}")
        hdr = bytes([_BLE_SOF, (_BLE_FRAME_OVERHEAD + len(record)) & 0xFF, flags & 0xFF, cmd_id & 0xFF])
        with self._lock:
            if check_replay:
                self._check_replay(seq)
            try:
                pt = self._rx.decrypt(self._iv(seq), ct, ble_aad(self.rx_dir, self.channel_id, seq, hdr))
            except self._InvalidTag as e:
                raise MdTsError("BAD_TAG", "BLE record failed AES-GCM authentication") from e
            if check_replay:
                self._commit_replay(seq)
        return pt

    def seal(self, keyexpr: str, plaintext: bytes, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encrypt one topic payload; returns the zenoh envelope to publish."""
        with self._lock:
            seq = self.tx_seq
            if seq > 0xFFFFFFFF:
                raise MdTsError("SEQ_EXHAUSTED", "TX sequence space exhausted; renegotiate")
            self.tx_seq += 1
        ct = self._tx.encrypt(self._iv(seq), bytes(plaintext),
                              zenoh_aad(self.tx_dir, self.channel_id, seq, keyexpr, encoding))
        return encode_enc_envelope(self._record(seq, ct))

    def open(self, keyexpr: str, record: bytes, encoding: str = DEFAULT_ENCODING, *,
             check_replay: bool = True) -> bytes:
        """Authenticate + decrypt one sealed record. `check_replay=False` verifies
        without consuming the replay window (for passive monitors)."""
        seq, ct = self._split(record)
        if seq == 0:
            raise MdTsError("BAD_RECORD", "seq 0 is reserved for handshake confirms")
        with self._lock:
            if check_replay:
                self._check_replay(seq)
            try:
                pt = self._rx.decrypt(self._iv(seq), ct,
                                      zenoh_aad(self.rx_dir, self.channel_id, seq, keyexpr, encoding))
            except self._InvalidTag as e:
                raise MdTsError("AUTH_FAILED", f"record failed authentication on {keyexpr}") from e
            if check_replay:
                self._commit_replay(seq)
        return pt

    def _check_replay(self, seq: int) -> None:
        if self._rx_max == 0 or seq > self._rx_max:
            return
        diff = self._rx_max - seq
        if diff >= REPLAY_WINDOW:
            raise MdTsError("REPLAY", f"seq {seq} is outside the replay window")
        if self._rx_bits >> diff & 1:
            raise MdTsError("REPLAY", f"seq {seq} was already received")

    def _commit_replay(self, seq: int) -> None:
        if self._rx_max == 0:
            self._rx_max, self._rx_bits = seq, 1
        elif seq > self._rx_max:
            shift = seq - self._rx_max
            self._rx_bits = 1 if shift >= REPLAY_WINDOW else ((self._rx_bits << shift) | 1) & ((1 << REPLAY_WINDOW) - 1)
            self._rx_max = seq
        else:
            self._rx_bits |= 1 << (self._rx_max - seq)


def open_envelope(session: Optional[Session], keyexpr: str, payload: bytes, *,
                  check_replay: bool = True) -> Optional[bytes]:
    """Plaintext for `payload`: as-is if it is not an envelope, decrypted if sealed and
    a session is up, None if it is sealed but undecryptable (or a handshake frame)."""
    env = decode_envelope(payload)
    if env is None:
        return bytes(payload)
    kind, body = env
    if kind != "encrypted" or session is None:
        return None
    try:
        return session.open(keyexpr, body, check_replay=check_replay)
    except MdTsError:
        return None


# ── identity ─────────────────────────────────────────────────────────────────
def default_identity_path() -> str:
    return os.environ.get("FREEWHEEL_IDENTITY_PATH") or os.path.expanduser("~/.config/freewheel/identity.json")


def legacy_identity_path() -> str:
    """Pre-1.0 config location, still read so an existing pairing keeps working."""
    return (os.environ.get(_LEGACY_IDENTITY_ENV)
            or os.path.expanduser(f"~/.config/{_LEGACY_CONFIG_DIR}/identity.json"))


@dataclass
class Identity:
    """Static X25519 client identity + known robot public keys (`~/.config/freewheel/identity.json`)."""

    client_id: bytes
    key_version: int
    private_key: bytes
    public_key: bytes
    robot_public_key: Optional[bytes] = None
    path: Optional[str] = None
    known_robots: dict = None

    def __post_init__(self):
        if self.known_robots is None:
            self.known_robots = {}

    @classmethod
    def generate(cls, key_version: int = 1) -> "Identity":
        priv = random_nonzero(32)
        return cls(random_nonzero(16), key_version, priv, x25519_public(priv))

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(os.path.expanduser(path), encoding="utf-8") as fh:
            raw = json.load(fh)
        robot = raw.get("default_robot_public_key_hex") or ""
        known_raw = raw.get("known_robots")
        known = ({str(k): dict(v) for k, v in known_raw.items() if isinstance(v, dict)}
                 if isinstance(known_raw, dict) else {})
        return cls(
            client_id=_nonzero(bytes.fromhex(raw["client_id_hex"]), 16, "client_id"),
            key_version=int(raw.get("key_version", 1)),
            private_key=_nonzero(bytes.fromhex(raw["private_key_hex"]), 32, "private_key"),
            public_key=_nonzero(bytes.fromhex(raw["public_key_hex"]), 32, "public_key"),
            robot_public_key=bytes.fromhex(robot) if robot else None,
            path=os.path.expanduser(path),
            known_robots=known,
        )

    @classmethod
    def load_default(cls) -> Optional["Identity"]:
        """Load `~/.config/freewheel/identity.json` (or the legacy config path if present)."""
        for p in (default_identity_path(), legacy_identity_path()):
            if os.path.exists(p):
                return cls.load(p)
        return None

    @classmethod
    def load_or_create(cls, path: Optional[str] = None) -> "Identity":
        """Load existing identity, or generate + persist a fresh one at `~/.config/freewheel/identity.json`."""
        if path:
            p = os.path.expanduser(path)
            if os.path.exists(p):
                return cls.load(p)
            ident = cls.generate()
            ident.save(p)
            return ident
        existing = cls.load_default()
        if existing is not None:
            return existing
        ident = cls.generate()
        ident.save(default_identity_path())
        return ident

    def lookup_robot_key(self, *, ble_address: str = "", ssid: str = "", host: str = "",
                         device_name: str = "", allow_default: bool = True) -> Optional[bytes]:
        """Look up a paired robot's static X25519 public key by BLE address, SSID, name, or IP."""
        keys = [k for k in (ble_address, ssid, device_name, host) if k]
        for k in keys:
            rec = self.known_robots.get(k)
            if isinstance(rec, dict) and rec.get("public_key_hex"):
                try:
                    return _nonzero(bytes.fromhex(rec["public_key_hex"]), 32, "robot_pub")
                except ValueError:
                    continue
        for rec in self.known_robots.values():
            if not isinstance(rec, dict) or not rec.get("public_key_hex"):
                continue
            if ((ble_address and rec.get("ble_address") == ble_address)
                    or (ssid and rec.get("ssid") == ssid)
                    or (device_name and rec.get("device_name") == device_name)
                    or (host and host != "192.168.7.1" and rec.get("host") == host)):
                try:
                    return _nonzero(bytes.fromhex(rec["public_key_hex"]), 32, "robot_pub")
                except ValueError:
                    continue
        return self.robot_public_key if allow_default else None

    def remember_robot(self, robot_public_key: bytes, *, ble_address: str = "", ssid: str = "",
                       device_name: str = "", host: str = "") -> None:
        import time as _time
        pub = _nonzero(robot_public_key, 32, "robot_public_key")
        self.robot_public_key = pub
        key = ble_address or ssid or device_name or host or "default"
        prev = dict(self.known_robots.get(key) or {})
        prev.update({
            "public_key_hex": pub.hex(),
            "ble_address": ble_address or prev.get("ble_address", ""),
            "ssid": ssid or prev.get("ssid", ""),
            "device_name": device_name or prev.get("device_name", ""),
            "host": host or prev.get("host", ""),
            "updated_at": _time.time(),
        })
        self.known_robots[key] = prev

    def save(self, path: Optional[str] = None) -> str:
        """Write atomically with 0600 permissions. Never overwrites a different identity."""
        p = os.path.expanduser(path or self.path or default_identity_path())
        if os.path.exists(p):
            try:
                disk = Identity.load(p)
                if disk.client_id != self.client_id:
                    raise MdTsError("IDENTITY_EXISTS", f"{p} holds a different identity; refusing to overwrite")
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                raise MdTsError("IDENTITY_CORRUPT", f"{p} is unreadable; refusing to overwrite") from e
            for k, rec in disk.known_robots.items():
                mine = self.known_robots.get(k)
                if mine is None or float(rec.get("updated_at", 0) or 0) > float(mine.get("updated_at", 0) or 0):
                    self.known_robots[k] = rec
            if not self.robot_public_key and disk.robot_public_key:
                self.robot_public_key = disk.robot_public_key
        os.makedirs(os.path.dirname(p), exist_ok=True)
        doc = {"client_id_hex": self.client_id.hex(), "key_version": self.key_version,
               "private_key_hex": self.private_key.hex(), "public_key_hex": self.public_key.hex(),
               "default_robot_public_key_hex": self.robot_public_key.hex() if self.robot_public_key else "",
               "known_robots": self.known_robots}
        tmp = f"{p}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, p)
        self.path = p
        return p


# ── client handshake (transport-agnostic state machine) ──────────────────────
class ClientHandshake:
    """Drive the client side. `start()` → SESSION_START envelope to publish on
    `app/security/session`; feed every `device/security/session` payload to
    `handle()`, which returns envelopes to publish. `session` is set (and
    `done` is True) once SERVER_CONFIRM verifies. Raises MdTsError on robot errors."""

    def __init__(self, identity: Identity, robot_public_key: Optional[bytes] = None,
                 client_nonce: Optional[bytes] = None):
        self.identity = identity
        self.robot_public_key = robot_public_key or identity.robot_public_key
        self._cnonce = client_nonce or random_nonzero(32)
        self.session: Optional[Session] = None
        self.done = False
        self.challenged = False

    def start(self) -> bytes:
        i = self.identity
        return encode_hs_envelope(build_session_start(i.client_id, i.key_version, self._cnonce))

    def handle(self, payload: bytes) -> list:
        env = decode_envelope(payload)
        if env is None or self.done:
            return []
        kind, body = env
        i = self.identity
        if kind == "handshake":
            try:
                msg = parse_hs(body)
            except ValueError:
                return []
            if msg.client_id != i.client_id:
                return []                             # someone else's handshake
            if msg.msg_type == HS_ERROR:
                hint = PAIRING_HINT if msg.error_code in (ERR_UNAUTHORIZED, ERR_PUBKEY_MISMATCH,
                                                          ERR_PENDING_NOT_FINALIZED) else ""
                raise MdTsError(msg.error_name, "robot rejected the MD-TS session", hint)
            if msg.msg_type != HS_SESSION_CHALLENGE or self.session is not None:
                return []
            self.challenged = True
            if not self.robot_public_key:
                raise MdTsError("MISSING_ROBOT_KEY", "robot requires MD-TS but its public key is unknown",
                                PAIRING_HINT)
            th = transcript_hash(transport=TRANSPORT_ZENOH, client_id=i.client_id, key_version=i.key_version,
                                 client_pub=i.public_key, robot_pub=self.robot_public_key,
                                 client_nonce=self._cnonce, server_nonce=msg.nonce, channel_id=msg.channel_id)
            kc, ks = derive_keys(x25519(i.private_key, self.robot_public_key), self._cnonce, msg.nonce,
                                 TRANSPORT_ZENOH, th)
            self.session = Session(ROLE_CLIENT, msg.channel_id, th, kc, ks)
            return [encode_enc_envelope(self.session.seal_confirm(i.client_id, i.key_version,
                                                                   APP_SECURITY_KEYEXPR))]
        if kind == "encrypted" and self.session is not None:
            self.session.open_confirm(body, i.client_id, i.key_version, DEVICE_SECURITY_KEYEXPR)
            self.done = True
        return []


def negotiate(identity: Identity, publish: Callable[[bytes], None], recv: Callable[[float], Optional[bytes]], *,
              robot_public_key: Optional[bytes] = None, mode: str = "auto", timeout: float = 2.0,
              probe_window: float = 0.6, resend_s: float = 0.25, clock=None) -> Optional[Session]:
    """Run the client handshake over caller-provided I/O.

    publish(envelope) sends on `app/security/session`; recv(timeout) returns the next
    `device/security/session` payload or None. mode "auto": no answer within
    `probe_window` → None (robot speaks plaintext). mode "md-ts": no answer within
    `timeout` → MdTsError. Robot errors always raise."""
    import time
    clock = clock or time.monotonic
    hs = ClientHandshake(identity, robot_public_key)
    start = hs.start()
    window = timeout if mode == "md-ts" else probe_window
    t0 = clock()
    last = None
    while not hs.done:
        now = clock()
        limit = timeout if hs.challenged else window
        if now - t0 > limit:
            if not hs.challenged and mode != "md-ts":
                return None
            raise MdTsError("HANDSHAKE_TIMEOUT", "no SESSION_CHALLENGE" if not hs.challenged
                            else "no SERVER_CONFIRM")
        if not hs.challenged and (last is None or now - last >= resend_s):
            publish(start)
            last = now
        payload = recv(0.05)
        if payload is None:
            continue
        for out in hs.handle(payload):
            publish(out)
    return hs.session


# ── robot side (simulator) ───────────────────────────────────────────────────
class Responder:
    """Robot-side handshake for the SITL peer. `authorized` maps client_id -> client
    public key (what a BLE button-pairing would have stored)."""

    def __init__(self, robot_private_key: bytes, authorized: dict, server_nonce=None, channel_id=None):
        self.private_key = robot_private_key
        self.public_key = x25519_public(robot_private_key)
        self.authorized = dict(authorized)
        self._snonce = server_nonce
        self._chid = channel_id
        self._pending = None                      # (msg, session)
        self.session: Optional[Session] = None

    def handle(self, payload: bytes) -> Optional[bytes]:
        """Process one `app/security/session` payload; returns a reply envelope or None."""
        env = decode_envelope(payload)
        if env is None:
            return None
        kind, body = env
        if kind == "handshake":
            try:
                msg = parse_hs(body)
            except ValueError:
                return None
            if msg.msg_type != HS_SESSION_START:
                return None
            pub = self.authorized.get(msg.client_id)
            if pub is None:
                return encode_hs_envelope(build_error(msg.client_id, msg.key_version, ERR_UNAUTHORIZED))
            snonce = self._snonce or random_nonzero(32)
            chid = self._chid or random_nonzero(8)
            th = transcript_hash(transport=TRANSPORT_ZENOH, client_id=msg.client_id, key_version=msg.key_version,
                                 client_pub=pub, robot_pub=self.public_key, client_nonce=msg.nonce,
                                 server_nonce=snonce, channel_id=chid)
            kc, ks = derive_keys(x25519(self.private_key, pub), msg.nonce, snonce, TRANSPORT_ZENOH, th)
            self._pending = (msg, Session(ROLE_SERVER, chid, th, kc, ks))
            self.session = None
            return encode_hs_envelope(build_session_challenge(msg.client_id, msg.key_version, snonce, chid))
        if kind == "encrypted" and self._pending is not None:
            msg, sess = self._pending
            try:
                sess.open_confirm(body, msg.client_id, msg.key_version, APP_SECURITY_KEYEXPR)
            except MdTsError:
                return None
            self._pending = None
            self.session = sess
            return encode_enc_envelope(sess.seal_confirm(msg.client_id, msg.key_version, DEVICE_SECURITY_KEYEXPR))
        return None
