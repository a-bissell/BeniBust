"""Zenoh unicast session handshake (clean-room, RE'd from libmondo_native.so).

A real robot's zenoh-pico runs a full transport session over the `mdZenohOverUcp`
link before it processes `Push`/`Query`. This module encodes/decodes the four
handshake transport messages — read from the shipped codec (Ghidra via REA):

    client → InitSyn   INIT(mid 1) | S(0x40) | Z(0x80)   @_z_t_msg_make_init_syn 0x203f44
    robot  → InitAck   INIT | A(0x20) | S | [Z]          @_z_init_decode 0x20ad4c
    client → OpenSyn   OPEN(mid 2) | T(0x40)             @_z_t_msg_make_open_syn 0x203f9c
    robot  → OpenAck   OPEN | A(0x20)                    @_z_open_decode 0x20afd8

Driven by `_z_unicast_open_client` (0x2162b4). Constants from the app's build:
protocol **version 0x09** (Zenoh 1.0), batch size **2048**, SN-resolution 2²⁸
(2 bits), lease **10 s**, a QoS extension (id 7 / `0x27`, value 1). Integers are
zint (LEB128) except the fixed u16 batch size (little-endian).

STATIC/UNTESTED on hardware: byte layout matches the shipped encoder; whether a
real robot completes the handshake is what the SDK's session lets you find out.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .zenoh_pico import enc_zint, _Reader   # reuse the varint + reader

# transport message IDs (low 5 bits of the header) — this build
MID_INIT, MID_OPEN, MID_CLOSE, MID_KEEPALIVE, MID_FRAME, MID_FRAGMENT, MID_JOIN = range(1, 8)
FLAG_A = 0x20          # Ack
FLAG_S = 0x40          # INIT: size params (whatami + batch) present
FLAG_T = 0x40          # OPEN: lease is in seconds (value /= 1000)
FLAG_Z = 0x80          # extensions follow

# app constants (from _z_t_msg_make_init_syn / make_open_syn)
PROTO_VERSION = 0x09
BATCH_SIZE = 2048
SN_RES_BITS = 2        # 2 → 2^28 resolution
WHATAMI_BYTE = 0x09    # fixed whatami|qos byte the app sends
QOS_EXT = 0x27         # ext header: ZInt ext, id 7, mandatory
QOS_VALUE = 1
LEASE_MS = 10000


class ZenohSessionError(ValueError):
    pass


@dataclass
class InitInfo:
    is_ack: bool
    version: int
    sn_res_bits: int
    zid: bytes
    whatami: int = 0
    qos: int = 0
    batch_size: int = 0
    cookie: bytes = b""


@dataclass
class OpenInfo:
    is_ack: bool
    lease_ms: int
    initial_sn: int
    cookie: bytes = b""


def _res_zidlen_byte(sn_res_bits: int, zid_len: int) -> int:
    return (sn_res_bits & 3) | (((zid_len - 1) & 0xF) << 4)


# ── encode ───────────────────────────────────────────────────────────────────
def encode_init_syn(zid: bytes) -> bytes:
    """Client InitSyn. header 0xc1 = INIT|S|Z; version, (snRes|zidLen), zid,
    whatami|qos byte, u16 batch (LE), then the QoS extension."""
    b = bytearray()
    b.append(MID_INIT | FLAG_S | FLAG_Z)                 # 0xc1
    b.append(PROTO_VERSION)
    b.append(_res_zidlen_byte(SN_RES_BITS, len(zid)))
    b += zid
    b.append(WHATAMI_BYTE)                               # S block
    b += struct.pack("<H", BATCH_SIZE)
    b.append(QOS_EXT)                                    # Z block: QoS ext
    b += enc_zint(QOS_VALUE)
    return bytes(b)


def encode_init_ack(zid: bytes, *, batch_size: int = BATCH_SIZE,
                    whatami_byte: int = WHATAMI_BYTE, cookie: bytes = b"") -> bytes:
    """Robot InitAck (used by the SITL sim). header = INIT|A|S."""
    b = bytearray()
    b.append(MID_INIT | FLAG_A | FLAG_S)                 # 0x61
    b.append(PROTO_VERSION)
    b.append(_res_zidlen_byte(SN_RES_BITS, len(zid)))
    b += zid
    b.append(whatami_byte)
    b += struct.pack("<H", batch_size)
    b += enc_zint(len(cookie)) + cookie                  # A block: cookie slice
    return bytes(b)


def encode_open_syn(initial_sn: int, cookie: bytes, lease_ms: int = LEASE_MS) -> bytes:
    """Client OpenSyn. header 0x42 = OPEN|T (lease in seconds); lease/1000,
    initial SN, then the cookie echoed from InitAck."""
    b = bytearray()
    b.append(MID_OPEN | FLAG_T)                          # 0x42
    b += enc_zint(lease_ms // 1000)
    b += enc_zint(initial_sn)
    b += enc_zint(len(cookie)) + cookie                  # cookie (0x20 clear → present)
    return bytes(b)


def encode_open_ack(initial_sn: int, lease_ms: int = LEASE_MS) -> bytes:
    """Robot OpenAck (used by the SITL sim). header 0x22 = OPEN|A; lease(ms), SN."""
    b = bytearray()
    b.append(MID_OPEN | FLAG_A)                          # 0x22
    b += enc_zint(lease_ms)
    b += enc_zint(initial_sn)
    return bytes(b)


# ── decode ───────────────────────────────────────────────────────────────────
def decode_transport(data: bytes):
    """Decode one transport message (InitInfo / OpenInfo / ('close'|'keepalive'|…))."""
    r = _Reader(data)
    h = r.u8()
    mid = h & 0x1F
    if mid == MID_INIT:
        return _decode_init(r, h)
    if mid == MID_OPEN:
        return _decode_open(r, h)
    return (("close" if mid == MID_CLOSE else "keepalive" if mid == MID_KEEPALIVE
             else f"mid{mid}"), h)


def _decode_init(r: _Reader, h: int) -> InitInfo:
    version = r.u8()
    fb = r.u8()
    sn_res_bits = fb & 3
    zid_len = (fb >> 4) + 1
    zid = r.take(zid_len)
    info = InitInfo(bool(h & FLAG_A), version, sn_res_bits, zid)
    if h & FLAG_S:
        wb = r.u8()
        info.whatami = wb & 3
        info.qos = (wb >> 2) & 3
        info.batch_size = struct.unpack("<H", r.take(2))[0]
    if h & FLAG_A:                                        # cookie (InitAck only)
        info.cookie = r.take(r.zint())
    return info


def _decode_open(r: _Reader, h: int) -> OpenInfo:
    lease = r.zint()
    if h & FLAG_T:
        lease *= 1000
    initial_sn = r.zint()
    info = OpenInfo(bool(h & FLAG_A), lease, initial_sn)
    if not (h & FLAG_A):                                  # cookie only in OpenSyn
        info.cookie = r.take(r.zint())
    return info


def is_init_ack(data: bytes) -> bool:
    return bool(data) and (data[0] & 0x3F) == (MID_INIT | FLAG_A)   # 0x21


def is_open_ack(data: bytes) -> bool:
    return bool(data) and (data[0] & 0x3F) == (MID_OPEN | FLAG_A)   # 0x22


def is_transport_msg(data: bytes) -> bool:
    """True if the batch's first byte is a transport message (mid 1..7), i.e. not
    a network message (0x19..0x1f) — used to split handshake msgs from data."""
    return bool(data) and 1 <= (data[0] & 0x1F) <= 7
