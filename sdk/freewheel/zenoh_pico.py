"""zenoh-pico wire decoder — the batch *inside* each A7 DATA frame.

Reverse-engineered from the actual zenoh-pico linked into
`libmondo_native.so` (Ghidra via REA). This decodes the real Zenoh 1.0 wire
protocol as that build emits it — not a heuristic. Every structure below was read
from a decompiled `_z_*_decode` function; the address is cited inline.

Layering (see also zenoh.py for the A4-A7 link framing that wraps this):
    A7 DATA payload  =  zenoh-pico batch
    batch            =  transport message(s)            (_z_transport_message_decode @0x20b5c0)
    FRAME (tmid 5)   =  SN(zint) [+exts] + network msgs  (_z_frame_decode @0x20b1a8)
    PUSH (nmid 0x1d) =  WireExpr [+exts] + PushBody       (_z_push_decode @0x20f290)
    PushBody         =  PUT (1) | DEL (2)                 (_z_push_body_decode @0x2068b8)
    PUT              =  [Timestamp] [Encoding] [exts] Payload

Integers are LEB128 varints (little-endian base-128, high bit = continue; up to 9
continuation bytes). Verified against `_z_zint64_decode` @0x208b2c.

This build's message IDs (the low 5 bits of each header byte):
  transport: INIT 1, OPEN 2, CLOSE 3, KEEP_ALIVE 4, FRAME 5, FRAGMENT 6, JOIN 7
  network:   INTEREST 0x19, RESPONSE_FINAL 0x1a, RESPONSE 0x1b, REQUEST 0x1c,
             PUSH 0x1d, DECLARE 0x1e, OAM 0x1f
  push body: PUT 1, DEL 2        declaration: DECL_KEXPR 0 (resource mapping)

STATIC-ONLY: read from the shipped codec, not confirmed against a live capture.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

# ── message IDs (low 5 bits of the header) ───────────────────────────────────
_T_INIT, _T_OPEN, _T_CLOSE, _T_KEEPALIVE, _T_FRAME, _T_FRAGMENT, _T_JOIN = range(1, 8)
_N_INTEREST, _N_RESPONSE_FINAL, _N_RESPONSE = 0x19, 0x1A, 0x1B
_N_REQUEST, _N_PUSH, _N_DECLARE, _N_OAM = 0x1C, 0x1D, 0x1E, 0x1F
_B_PUT, _B_DEL = 1, 2
_D_KEXPR = 0                       # DeclareKeyExpr → resource-id → keyexpr mapping

# header flag bits (shared conventions, confirmed per function)
_FLAG_Z = 0x80                     # extensions follow
_FLAG_N = 0x20                     # WireExpr has a suffix (named)
_FLAG_M = 0x40                     # WireExpr mapping present
_PUT_T, _PUT_E, _PUT_Z = 0x20, 0x40, 0x80   # timestamp / encoding / extensions

# zenoh 1.x predefined encoding ids (zenoh-pico src/api/encoding.c). The decoder
# always keeps the raw id + schema, so unknown ids are never lost.
ENC_ZENOH_BYTES = 0
ENC_ZENOH_STRING = 1
ENC_APPLICATION_OCTET_STREAM = 3
ENC_APPLICATION_JSON = 5
ENC_APPLICATION_PROTOBUF = 13     # ZP_ENCODING_APPLICATION_PROTOBUF (what the app sends)
ENCODING_NAMES = {0: "zenoh/bytes", 1: "zenoh/string", 2: "zenoh/serialized",
                  3: "application/octet-stream", 4: "text/plain", 5: "application/json",
                  6: "text/json", 13: "application/protobuf", 16: "image/png", 17: "image/jpeg"}


class ZenohPicoError(ValueError):
    """Malformed zenoh-pico batch."""


@dataclass
class Timestamp:
    time: int                      # NTP64
    id: bytes                      # ZenohID (≤16 bytes)


@dataclass
class Encoding:
    id: int
    schema: bytes = b""

    def __str__(self) -> str:
        name = ENCODING_NAMES.get(self.id, f"enc#{self.id}")
        return f"{name}" + (f";{self.schema.decode('utf-8', 'replace')}" if self.schema else "")


@dataclass
class Put:
    keyexpr: str
    payload: bytes
    encoding: Optional[Encoding] = None
    timestamp: Optional[Timestamp] = None
    kind: str = field(default="PUT", init=False)

    def value(self) -> str:
        """Best-effort human view of the payload, guided by the encoding. Short
        binary values show as hex (a 1-byte 0x64 is a number, not the letter 'd')."""
        name = ENCODING_NAMES.get(self.encoding.id) if self.encoding else None
        if name in ("zenoh/string", "text/plain", "text/json", "application/json"):
            return self.payload.decode("utf-8", "replace")
        if len(self.payload) >= 4 and _is_mostly_text(self.payload):
            return self.payload.decode("utf-8", "replace")
        return self.payload.hex()


@dataclass
class Del:
    keyexpr: str
    timestamp: Optional[Timestamp] = None
    kind: str = field(default="DEL", init=False)


@dataclass
class DeclareKeyExpr:
    rid: int
    keyexpr: str
    kind: str = field(default="DECLARE_KEXPR", init=False)


@dataclass
class OtherMessage:
    """A message we recognize but don't fully decode (INIT/OPEN/REQUEST/…)."""
    kind: str
    mid: int


Message = Union[Put, Del, DeclareKeyExpr, OtherMessage]


def _is_mostly_text(b: bytes) -> bool:
    if not b:
        return False
    printable = sum(1 for c in b if 0x20 <= c <= 0x7E or c in (9, 10, 13))
    return printable / len(b) > 0.85


class _Reader:
    """Cursor over a batch. Raises ZenohPicoError (err 0x89 in the native code) on
    underrun, matching the decompiled bounds checks."""

    def __init__(self, data: bytes):
        self.b = data
        self.i = 0
        self.n = len(data)

    def remaining(self) -> int:
        return self.n - self.i

    def u8(self) -> int:
        if self.i >= self.n:
            raise ZenohPicoError("underrun (u8)")
        v = self.b[self.i]
        self.i += 1
        return v

    def zint(self) -> int:
        """LEB128 varint — _z_zint64_decode @0x208b2c."""
        out = 0
        for k in range(9):                      # up to 9 continuation bytes
            c = self.u8()
            if c < 0x80:
                return out | (c << (7 * k))
            out |= (c & 0x7F) << (7 * k)
        return out | (self.u8() << 63)          # 10th byte: full 8 bits at shift 63/56

    def take(self, n: int) -> bytes:
        if n < 0 or self.remaining() < n:
            raise ZenohPicoError("underrun (bytes)")
        v = self.b[self.i:self.i + n]
        self.i += n
        return bytes(v)

    def string(self) -> str:                    # _z_string_decode @0x209a6c
        return self.take(self.zint()).decode("utf-8", "replace")

    def zbytes(self) -> bytes:                  # _z_bytes_decode @0x2092f8 (single slice)
        return self.take(self.zint())

    def skip_exts(self) -> None:                # _z_msg_ext_skip_non_mandatories @0x20bfbc
        while True:
            eh = self.u8()
            enc = eh & 0x60
            if enc == 0x20:                     # ZInt body
                self.zint()
            elif enc == 0x40:                   # ZBuf body
                self.take(self.zint())
            # 0x00 = Unit (no body)
            if not (eh & 0x80):                 # more-extensions bit
                break


class ZenohPicoDecoder:
    """Stateful zenoh-pico batch decoder. Keeps the resource-id → key-expression
    table from DeclareKeyExpr messages so scoped WireExprs resolve to full topics.
    One decoder per session (feed it successive A7 batches)."""

    def __init__(self):
        self.resources: Dict[int, str] = {}     # rid → declared key-expression prefix

    # -- public ----------------------------------------------------------------
    def decode_batch(self, data: bytes) -> List[Message]:
        """Decode one A7 DATA batch → a list of messages. Stops at the first
        structural error (returning what was decoded so far) rather than raising,
        so a monitor keeps running on a malformed frame."""
        r = _Reader(data)
        out: List[Message] = []
        try:
            while r.remaining() > 0:
                self._transport_message(r, out)
        except ZenohPicoError:
            pass
        return out

    # -- transport layer (_z_transport_message_decode @0x20b5c0) ---------------
    def _transport_message(self, r: _Reader, out: List[Message]) -> None:
        h = r.u8()
        mid = h & 0x1F
        if mid == _T_FRAME:                      # SN + [exts] + network messages
            r.zint()
            if h & _FLAG_Z:
                r.skip_exts()
            while r.remaining() > 0:
                self._network_message(r, out)
        elif mid == _T_KEEPALIVE:
            if h & _FLAG_Z:
                r.skip_exts()
        elif mid == _T_CLOSE:
            r.u8()                               # reason
        elif mid in (0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F):
            # Some links feed network messages directly (no Frame wrapper).
            r.i -= 1
            self._network_message(r, out)
        else:                                    # INIT/OPEN/JOIN/FRAGMENT — not for telemetry
            out.append(OtherMessage(_T_NAMES.get(mid, "transport?"), mid))
            raise ZenohPicoError("cannot skip session transport message")

    # -- network layer (_z_network_message_decode @0x210660) -------------------
    def _network_message(self, r: _Reader, out: List[Message]) -> None:
        h = r.u8()
        mid = h & 0x1F
        if mid == _N_PUSH:                       # _z_push_decode @0x20f290
            ke = self._wireexpr(r, has_suffix=bool(h & _FLAG_N), mapping=bool(h & _FLAG_M))
            if h & _FLAG_Z:
                r.skip_exts()
            self._push_body(r, ke, out)
        elif mid == _N_DECLARE:                  # _z_declaration_decode @0x211ad4
            if h & _FLAG_N:
                r.zint()                         # interest/request id (zint32)
            if h & _FLAG_Z:
                r.skip_exts()
            self._declaration(r, out)
        else:                                    # REQUEST/RESPONSE/INTEREST/OAM — recorded, not parsed
            out.append(OtherMessage(_N_NAMES.get(mid, "network?"), mid))
            raise ZenohPicoError("cannot skip this network message")

    # -- WireExpr (_z_wireexpr_decode @0x20602c) -------------------------------
    def _wireexpr(self, r: _Reader, has_suffix: bool, mapping: bool) -> str:
        scope = r.zint()                         # resource id (0 = fully literal)
        suffix = r.string() if has_suffix else ""
        if scope == 0:
            return suffix
        prefix = self.resources.get(scope)
        return (prefix + suffix) if prefix is not None else f"@{scope}{suffix}"

    # -- PushBody: Put / Del (_z_push_body_decode @0x2068b8) --------------------
    def _push_body(self, r: _Reader, keyexpr: str, out: List[Message]) -> None:
        bh = r.u8()
        bmid = bh & 0x1F
        if bmid == _B_PUT:
            ts = self._timestamp(r) if bh & _PUT_T else None
            enc = self._encoding(r) if bh & _PUT_E else None
            if bh & _PUT_Z:
                r.skip_exts()
            out.append(Put(keyexpr, r.zbytes(), enc, ts))
        elif bmid == _B_DEL:
            ts = self._timestamp(r) if bh & _PUT_T else None
            if bh & _PUT_Z:
                r.skip_exts()
            out.append(Del(keyexpr, ts))
        else:
            raise ZenohPicoError(f"bad push body mid {bmid}")

    def _timestamp(self, r: _Reader) -> Timestamp:
        t = r.zint()                             # NTP64
        return Timestamp(t, r.take(r.u8()))      # 1-byte len + id bytes

    def _encoding(self, r: _Reader) -> Encoding:  # _z_encoding_decode @0x209e4c
        combined = r.zint()
        enc = Encoding(combined >> 1)
        if combined & 1:                         # has schema
            enc.schema = r.take(r.zint())
        return enc

    # -- Declaration (_z_declaration_decode @0x211ad4) -------------------------
    def _declaration(self, r: _Reader, out: List[Message]) -> None:
        dh = r.u8()
        did = dh & 0x1F
        if did == _D_KEXPR:                      # DeclareKeyExpr: rid + WireExpr
            rid = r.zint()
            ke = self._wireexpr(r, has_suffix=bool(dh & _FLAG_N), mapping=True)
            if dh & _FLAG_Z:
                r.skip_exts()
            self.resources[rid] = ke
            out.append(DeclareKeyExpr(rid, ke))
        else:
            out.append(OtherMessage(f"declare#{did}", did))
            raise ZenohPicoError("cannot skip this declaration")


_T_NAMES = {1: "INIT", 2: "OPEN", 3: "CLOSE", 4: "KEEP_ALIVE", 5: "FRAME",
            6: "FRAGMENT", 7: "JOIN"}
_N_NAMES = {0x19: "INTEREST", 0x1A: "RESPONSE_FINAL", 0x1B: "RESPONSE",
            0x1C: "REQUEST", 0x1D: "PUSH", 0x1E: "DECLARE", 0x1F: "OAM"}


def decode_batch(data: bytes, decoder: Optional[ZenohPicoDecoder] = None) -> List[Message]:
    """Convenience one-shot decode. Pass a persistent ZenohPicoDecoder to retain
    the resource-id → key-expression table across batches."""
    return (decoder or ZenohPicoDecoder()).decode_batch(data)


# ── encoder (byte-exact to the app; see _z_*_encode @addr) ────────────────────
# Mirrors _z_push_encode @0x20f08c / _z_push_body_encode @0x206550 /
# _z_frame_encode @0x20b114 — the exact message layout libmondo_native.so emits.
_FRAME_R = 0x20                    # FRAME reliable flag (header 0x05 | 0x20)


def enc_zint(v: int) -> bytes:     # _z_zint64 encode (LEB128, LE base-128)
    out = bytearray()
    v &= (1 << 64) - 1
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def enc_string(s: str) -> bytes:   # _z_string_encode: zint(len) + utf-8
    data = s.encode("utf-8")
    return enc_zint(len(data)) + data


def enc_zbytes(b: bytes) -> bytes:  # _z_bytes_encode: zint(len) + bytes
    return enc_zint(len(b)) + bytes(b)


def enc_encoding(encoding: int, schema: bytes = b"") -> bytes:   # _z_encoding_encode @0x209cc4
    out = enc_zint((encoding << 1) | (1 if schema else 0))
    return out + (enc_zbytes(schema) if schema else b"")


def enc_timestamp(ts: Timestamp) -> bytes:
    return enc_zint(ts.time) + bytes([len(ts.id)]) + bytes(ts.id)


def _enc_push(keyexpr: str, body: bytes, *, scope: int = 0) -> bytes:
    """PUSH header + WireExpr + body. Header = PUSH|M, +N if there's a suffix,
    matching _z_push_encode's default (M set, no push-level extensions)."""
    suffix = keyexpr if scope == 0 else keyexpr    # literal suffix (scope 0 = fully literal)
    h = _N_PUSH | _FLAG_M
    we = enc_zint(scope)
    if suffix:
        h |= _FLAG_N
        we += enc_string(suffix)
    return bytes([h]) + we + body


def encode_put(keyexpr: str, payload: bytes, encoding: Optional[int] = None,
               timestamp: Optional[Timestamp] = None, scope: int = 0) -> bytes:
    """One PUSH→PUT network message. Put body = header(T/E) + [timestamp] +
    [encoding] + payload(ZBytes), the order _z_push_body_decode expects."""
    bh = _B_PUT
    parts = bytearray()
    if timestamp is not None:
        bh |= _PUT_T
    if encoding is not None:
        bh |= _PUT_E
    parts.append(bh)
    if timestamp is not None:
        parts += enc_timestamp(timestamp)
    if encoding is not None:
        parts += enc_encoding(encoding)
    parts += enc_zbytes(payload)
    return _enc_push(keyexpr, bytes(parts), scope=scope)


def encode_del(keyexpr: str, timestamp: Optional[Timestamp] = None, scope: int = 0) -> bytes:
    """One PUSH→DEL network message."""
    bh = _B_DEL
    parts = bytearray()
    if timestamp is not None:
        bh |= _PUT_T
    parts.append(bh)
    if timestamp is not None:
        parts += enc_timestamp(timestamp)
    return _enc_push(keyexpr, bytes(parts), scope=scope)


_D_SUBSCRIBER = 2      # DeclareSubscriber declaration id


def encode_declare_subscriber(sub_id: int, keyexpr: str, scope: int = 0) -> bytes:
    """A DECLARE network message carrying a DeclareSubscriber — so the robot routes
    matching key expressions (e.g. a `_rsp` topic) back to us. Layout from
    _z_declaration_encode @0x2110cc: declaration hdr (did 2 | N 0x20 | M 0x40) +
    zint(subId) + WireExpr; wrapped in a DECLARE network message (0x1e)."""
    decl = bytes([_D_SUBSCRIBER | _FLAG_N | _FLAG_M]) + enc_zint(sub_id) \
        + enc_zint(scope) + (enc_string(keyexpr) if keyexpr else b"")
    return bytes([_N_DECLARE]) + decl


def encode_frame(sn: int, *net_msgs: bytes, reliable: bool = True) -> bytes:
    """Wrap network messages in a transport FRAME — _z_frame_encode @0x20b114."""
    h = _T_FRAME | (_FRAME_R if reliable else 0)
    return bytes([h]) + enc_zint(sn) + b"".join(net_msgs)


def encode_batch(puts, sn: int = 0, reliable: bool = False) -> bytes:
    """Convenience: a FRAME of PUTs. puts = list of (keyexpr, payload[, encoding])."""
    msgs = [encode_put(p[0], p[1], p[2] if len(p) > 2 else None) for p in puts]
    return encode_frame(sn, *msgs, reliable=reliable)
