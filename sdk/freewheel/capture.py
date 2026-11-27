"""Capture & replay of UCP/zenoh traffic — the hardware-day record button.

On first contact with a real robot you want a faithful, SDK-independent record of
every byte on the wire, so you can re-decode it later (with a fixed decoder),
diff it against the SITL sim, and attach it to a bug report. This module records
raw datagrams in both directions to a line-delimited `.fwcap` file, then replays
them back through the clean-room decode stack offline.

A `.fwcap` file is JSONL: the first line is a header, every later line one
datagram::

    {"fwcap": 1, "host": "192.168.7.1", "port": 9007, "t0_unix": 1.73e9, "note": "..."}
    {"t": 0.0123, "dir": "rx", "raw": "51000000..."}
    {"t": 0.0124, "dir": "tx", "raw": "51100000..."}

`t` is seconds since `t0_unix`. The record is lossless at the UCP datagram layer:
decode is done after the fact by re-parsing, so a capture taken today stays
decodable as the decoders improve. (The raw `ucp:sync`/`ucp:ack`/`ucp:leav`
control strings on TX are not tapped — only framed datagrams are; RX records
everything, those strings included.)

Usage — record a live session::

    with Capture("beni-firstcontact.fwcap", host=ip) as cap, \\
         MondoClient(ip, listen_only=True, on_raw=cap.record_rx,
                     on_send=cap.record_tx) as robot:
        time.sleep(30)

…then decode it offline with `summarize(path)` / `decode_capture(path)`.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Iterator, List, Optional

from . import zenoh, zenoh_pico, zenoh_session
from .transport import HEADER, MAGIC, ACK, SYNC, LEAVE, ZENOH_CHANNELS, decode_segments

FWCAP_VERSION = 1


# ── writer ─────────────────────────────────────────────────────────────────────
class Capture:
    """Append-only `.fwcap` recorder. Thread-safe; `record_rx`/`record_tx` are the
    callbacks to hand to `UcpTransport`/`MondoClient` (`on_raw` / `on_send`)."""

    def __init__(self, path: str, host: Optional[str] = None, port: int = 9007,
                 note: str = ""):
        self.path = path
        self._lock = threading.Lock()
        self._t0 = time.monotonic()
        self.rx = 0
        self.tx = 0
        self._fh = open(path, "w", buffering=1)          # line-buffered
        header = {"fwcap": FWCAP_VERSION, "host": host, "port": port,
                  "t0_unix": time.time(), "note": note}
        self._fh.write(json.dumps(header) + "\n")

    def _write(self, direction: str, datagram: bytes) -> None:
        with self._lock:
            if self._fh.closed:
                return
            rec = {"t": round(time.monotonic() - self._t0, 6),
                   "dir": direction, "raw": bytes(datagram).hex()}
            self._fh.write(json.dumps(rec) + "\n")

    def record_rx(self, datagram: bytes) -> None:
        self.rx += 1
        self._write("rx", datagram)

    def record_tx(self, datagram: bytes) -> None:
        self.tx += 1
        self._write("tx", datagram)

    def attach(self, transport) -> None:
        """Chain this capture onto a live `UcpTransport`, preserving any existing
        `on_raw`/`on_send` callbacks."""
        prev_raw, prev_send = transport.on_raw, transport.on_send

        def _raw(d):
            self.record_rx(d)
            if prev_raw:
                prev_raw(d)

        def _send(d):
            self.record_tx(d)
            if prev_send:
                prev_send(d)

        transport.on_raw = _raw
        transport.on_send = _send

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ── reader ─────────────────────────────────────────────────────────────────────
@dataclass
class CaptureHeader:
    version: int
    host: Optional[str]
    port: int
    t0_unix: float
    note: str = ""


@dataclass
class Record:
    t: float
    dir: str                   # "rx" | "tx"
    raw: bytes


def read_capture(path: str):
    """Return (CaptureHeader, [Record, …]). Raises ValueError on a bad header."""
    recs: List[Record] = []
    with open(path) as fh:
        first = fh.readline()
        if not first:
            raise ValueError(f"{path}: empty capture")
        h = json.loads(first)
        if "fwcap" not in h:
            raise ValueError(f"{path}: not a .fwcap file (no header)")
        header = CaptureHeader(h["fwcap"], h.get("host"), h.get("port", 9007),
                               h.get("t0_unix", 0.0), h.get("note", ""))
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            recs.append(Record(r["t"], r["dir"], bytes.fromhex(r["raw"])))
    return header, recs


# ── offline decode ───────────────────────────────────────────────────────────
@dataclass
class DecodedEvent:
    t: float
    dir: str
    channel: Optional[int]           # UCP channel, or None for control strings
    kind: str                        # ucp-control | ucp | zenoh-<frame> | transport | put | del | ...
    detail: str
    keyexpr: Optional[str] = None
    extra: dict = field(default_factory=dict)


def _ucp_payload(datagram: bytes):
    """(channel, payload) for a framed UCP datagram, else (None, None)."""
    if len(datagram) < HEADER.size or datagram[0] != MAGIC:
        return None, None
    segs = decode_segments(datagram)           # strips the SACK trailer
    if segs:
        return segs[0]["channel"], segs[0]["payload"]
    flags, ack, seq, length, ts = HEADER.unpack_from(datagram, 0)
    channel = (flags >> 10) & 0x3
    payload = datagram[HEADER.size:length] if length <= len(datagram) else datagram[HEADER.size:]
    return channel, bytes(payload)


def decode_capture(path: str) -> Iterator[DecodedEvent]:
    """Re-decode a capture through the full clean-room stack: UCP → zenoh link →
    zenoh-pico (and the session handshake). Yields one `DecodedEvent` per decoded
    unit (a datagram may yield several: a FRAME batch can carry many Puts)."""
    _, recs = read_capture(path)
    pico = zenoh_pico.ZenohPicoDecoder()
    for rec in recs:
        d = rec.raw
        if d[:7] == ACK or d[:8] == SYNC or d[:8] == LEAVE:
            yield DecodedEvent(rec.t, rec.dir, None, "ucp-control",
                               d.split(b"\x00", 1)[0].decode("latin1", "replace"))
            continue
        ch, payload = _ucp_payload(d)
        if ch is None:
            yield DecodedEvent(rec.t, rec.dir, None, "unknown", f"{len(d)}B {d[:8].hex()}")
            continue
        if ch not in ZENOH_CHANNELS or not payload or payload[0] not in zenoh.ALL_TAGS:
            yield DecodedEvent(rec.t, rec.dir, ch, "ucp",
                               f"ch{ch} {len(payload)}B {payload[:8].hex()}")
            continue
        # zenoh-over-UCP link (reliable ch3, or unreliable ch0)
        for fr in zenoh.iter_frames(payload):
            if not fr.is_data:
                yield DecodedEvent(rec.t, rec.dir, ch, f"zenoh-{fr.type.name.lower()}",
                                   f"epoch={fr.epoch}", extra={"epoch": fr.epoch})
                continue
            batch = fr.payload
            # Only INIT/OPEN are the session handshake; FRAME (mid 5) *carries*
            # network messages (Push/Put) and must go to the pico decoder.
            if _is_session_msg(batch):
                info = zenoh_session.decode_transport(batch)
                yield DecodedEvent(rec.t, rec.dir, ch, "transport",
                                   _describe_transport(info), extra=_transport_fields(info))
                continue
            for m in pico.decode_batch(batch):
                yield _msg_event(rec, ch, m)


def _is_session_msg(batch: bytes) -> bool:
    """True only for INIT/OPEN transport messages (the unicast session handshake),
    NOT FRAME/FRAGMENT, which carry the network messages the pico decoder reads."""
    return bool(batch) and (batch[0] & 0x1F) in (zenoh_session.MID_INIT, zenoh_session.MID_OPEN)


def _transport_fields(info) -> dict:
    """Structured transport fields for the conformance ledger (no repr parsing)."""
    name = type(info).__name__
    if name == "InitInfo":
        return {"msg": "InitAck" if info.is_ack else "InitSyn", "is_ack": info.is_ack,
                "version": info.version, "batch_size": info.batch_size,
                "cookie_len": len(info.cookie), "zid": info.zid.hex()}
    if name == "OpenInfo":
        return {"msg": "OpenAck" if info.is_ack else "OpenSyn", "is_ack": info.is_ack,
                "lease_ms": info.lease_ms, "initial_sn": info.initial_sn,
                "cookie_len": len(info.cookie)}
    return {"msg": str(info)}


def _describe_transport(info) -> str:
    f = _transport_fields(info)
    if "version" in f:
        return (f"{f['msg']} v{f['version']} batch={f['batch_size']} "
                f"zid={f['zid']} cookie={f['cookie_len']}B")
    if "lease_ms" in f:
        return f"{f['msg']} lease={f['lease_ms']}ms sn={f['initial_sn']} cookie={f['cookie_len']}B"
    return f["msg"]


def _msg_event(rec: Record, ch: int, m) -> DecodedEvent:
    if isinstance(m, zenoh_pico.Put):
        enc = f" [{m.encoding}]" if m.encoding else ""
        return DecodedEvent(rec.t, rec.dir, ch, "put",
                            f"{m.keyexpr} ={_short(m.value())}{enc}", keyexpr=m.keyexpr)
    if isinstance(m, zenoh_pico.Del):
        return DecodedEvent(rec.t, rec.dir, ch, "del", m.keyexpr, keyexpr=m.keyexpr)
    if isinstance(m, zenoh_pico.DeclareKeyExpr):
        return DecodedEvent(rec.t, rec.dir, ch, "declare", repr(m))
    return DecodedEvent(rec.t, rec.dir, ch, type(m).__name__.lower(), repr(m))


def _short(v, n: int = 40) -> str:
    s = v.hex() if isinstance(v, (bytes, bytearray)) else str(v)
    return s if len(s) <= n else s[:n] + "…"


# ── summary ────────────────────────────────────────────────────────────────────
def summarize(path: str) -> str:
    """A human-readable decode summary of a capture — direction/channel tallies,
    the zenoh session outcome, and the set of key expressions seen."""
    header, recs = read_capture(path)
    from collections import Counter
    dirs = Counter(r.dir for r in recs)
    kinds: Counter = Counter()
    chans: Counter = Counter()
    topics: Counter = Counter()
    transport: List[str] = []
    for ev in decode_capture(path):
        kinds[ev.kind] += 1
        if ev.channel is not None:
            chans[ev.channel] += 1
        if ev.keyexpr:
            topics[ev.keyexpr] += 1
        if ev.kind == "transport":
            transport.append(f"{ev.dir}: {ev.detail}")
    span = recs[-1].t if recs else 0.0
    lines = [
        f"=== {path} ===",
        f"  host={header.host}:{header.port}  note={header.note!r}",
        f"  {len(recs)} datagrams over {span:.1f}s  "
        f"(rx {dirs['rx']}, tx {dirs['tx']})",
        "  decoded: " + "  ".join(f"{k}={v}" for k, v in kinds.most_common()),
        "  channels: " + "  ".join(f"ch{c}={n}" for c, n in sorted(chans.items())),
    ]
    if transport:
        lines.append("  zenoh session:")
        lines += [f"    {t}" for t in transport[:8]]
    if topics:
        lines.append(f"  key expressions ({len(topics)}):")
        lines += [f"    {ke}  ×{n}" for ke, n in topics.most_common(24)]
    return "\n".join(lines)
