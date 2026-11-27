"""Zenoh-over-UCP link framing (clean-room, from static RE of libmondo_native.so).

Reference: the protocol report §3b (`mdZenohOverUcp*`), in the research repository.
The robot's control
bus **and telemetry** ride zenoh-pico over this link framing, which itself rides on
UCP channel 0. This module decodes the **link layer** (the `A4`–`A7` frames) and
hands back the zenoh-pico DATA batches, driving the epoch state machine as it goes.

Two layers, two confidence levels:
  • LINK (this module's core) — the `A4`–`A7` framing, decoded exactly per the
    reconstructed decompiler reference. High confidence.
  • zenoh-pico batch (inside each `A7`) — the robot's own zenoh-pico encoding was
    NOT fully reversed. `keyexpr_candidates()` / `printable_strings()` do a
    best-effort heuristic extraction (zenoh key expressions are ASCII on the wire),
    clearly marked EXPERIMENTAL.

Frame format (1-byte tag; integers big-endian EXCEPT the A7 length, which is LE):
  A4  CONNECT  tag + epoch_id:u32 BE                      (5 B)   open an epoch
  A5  READY    tag + epoch_id:u32 BE                      (5 B)   setup done (both)
  A6  CLOSE    tag + epoch_id:u32 BE                      (5 B)   teardown
  A7  DATA     tag + id:u16 BE + len:u16 LE + len bytes           zenoh-pico batch

STATIC-ONLY: matches the decompiled decoder; not confirmed against a real robot.
"""
from __future__ import annotations

import enum
import os
import re
from collections import Counter, deque
from dataclasses import dataclass, field, replace
from typing import Callable, Iterator, List, Optional

from .transport import ZENOH_CHANNELS as _ZCH
from . import zenoh_pico

# ── tags / types ─────────────────────────────────────────────────────────────
TAG_CONNECT = 0xA4
TAG_READY = 0xA5
TAG_CLOSE = 0xA6
TAG_DATA = 0xA7

RESERVED_LEN = 0xFFFF          # A7 len 0xFFFF → protocol error -5 (parser reset)
MAX_DATA = 0x10000             # encoder cap on A7 payload


class FrameType(enum.IntEnum):
    CONNECT = 1
    READY = 2
    CLOSE = 3
    DATA = 4


_TAG_TO_TYPE = {TAG_CONNECT: FrameType.CONNECT, TAG_READY: FrameType.READY,
                TAG_CLOSE: FrameType.CLOSE, TAG_DATA: FrameType.DATA}
_TYPE_TO_TAG = {v: k for k, v in _TAG_TO_TYPE.items()}
ALL_TAGS = frozenset(_TAG_TO_TYPE)


class ZenohError(ValueError):
    """Malformed zenoh-over-UCP framing (maps to the native -5 protocol error)."""


@dataclass
class ZenohFrame:
    type: FrameType
    epoch: int                 # epoch id (u32 for control) or stream id (u16 for DATA)
    payload: bytes = b""       # zenoh-pico batch for DATA; empty for control

    @property
    def is_data(self) -> bool:
        return self.type is FrameType.DATA

    def __repr__(self) -> str:
        if self.is_data:
            return f"ZenohFrame(DATA sid={self.epoch} len={len(self.payload)})"
        return f"ZenohFrame({self.type.name} epoch={self.epoch})"


# ── strict decode / encode (one complete buffer) ─────────────────────────────
def iter_frames(buf: bytes) -> Iterator[ZenohFrame]:
    """Strictly decode a complete buffer (the §3b reference decoder). Yields
    ZenohFrame; raises ZenohError on malformed input. For a live stream (partial
    frames across datagrams, resync) use ZenohLink.feed()."""
    i, n = 0, len(buf)
    while i < n:
        tag = buf[i]
        t = _TAG_TO_TYPE.get(tag)
        if t is None:
            raise ZenohError(f"bad tag {tag:#04x} at offset {i}")
        if t is FrameType.DATA:
            if i + 5 > n:
                raise ZenohError("truncated A7 header")
            sid = int.from_bytes(buf[i + 1:i + 3], "big")
            ln = int.from_bytes(buf[i + 3:i + 5], "little")   # NOTE: little-endian
            if ln == RESERVED_LEN:
                raise ZenohError("reserved A7 length 0xFFFF")
            if i + 5 + ln > n:
                raise ZenohError("truncated A7 payload")
            yield ZenohFrame(t, sid, bytes(buf[i + 5:i + 5 + ln]))
            i += 5 + ln
        else:
            if i + 5 > n:
                raise ZenohError("truncated control frame")
            sid = int.from_bytes(buf[i + 1:i + 5], "big")
            if sid == 0:
                raise ZenohError("zero epoch id")
            yield ZenohFrame(t, sid, b"")
            i += 5


def encode_control(ftype: FrameType, epoch: int) -> bytes:
    """Encode an A4/A5/A6 control frame (tag + u32 BE epoch)."""
    if ftype is FrameType.DATA:
        raise ValueError("use encode_data for A7")
    if not (0 < epoch <= 0xFFFFFFFF):
        raise ValueError("epoch must be a nonzero u32")
    return bytes([_TYPE_TO_TAG[ftype]]) + epoch.to_bytes(4, "big")


def encode_data(sid: int, payload: bytes) -> bytes:
    """Encode an A7 DATA frame (tag + u16 BE id + u16 LE len + payload)."""
    if not (0 < sid <= 0xFFFF):
        raise ValueError("stream id must be a nonzero u16")
    if len(payload) >= MAX_DATA or len(payload) == RESERVED_LEN:
        raise ValueError(f"payload length {len(payload)} out of range")
    return (bytes([TAG_DATA]) + sid.to_bytes(2, "big")
            + len(payload).to_bytes(2, "little") + bytes(payload))


def encode_connect(epoch: int) -> bytes: return encode_control(FrameType.CONNECT, epoch)
def encode_ready(epoch: int) -> bytes:   return encode_control(FrameType.READY, epoch)
def encode_close(epoch: int) -> bytes:   return encode_control(FrameType.CLOSE, epoch)


# ── stateful streaming link ──────────────────────────────────────────────────
class EpochState(enum.Enum):
    IDLE = "idle"
    CONNECTING = "connecting"      # saw A4
    READY = "ready"                # saw A5
    CLOSED = "closed"              # saw A6


def _next_tag(b: bytes, start: int) -> Optional[int]:
    for j in range(start, len(b)):
        if b[j] in ALL_TAGS:
            return j
    return None


class ZenohLink:
    """Streaming zenoh-over-UCP decoder: feed raw channel-0 payloads, get frames.

    Buffers partial frames across feeds, resyncs on a bad tag (drops to the next
    known tag), tracks the connection epoch state machine, and fires callbacks.
    """

    def __init__(self,
                 on_connect: Optional[Callable[[int], None]] = None,
                 on_ready: Optional[Callable[[int], None]] = None,
                 on_close: Optional[Callable[[int], None]] = None,
                 on_data: Optional[Callable[[ZenohFrame], None]] = None,
                 log: Optional[Callable[[str], None]] = None):
        self._buf = bytearray()
        self._on_connect = on_connect
        self._on_ready = on_ready
        self._on_close = on_close
        self._on_data = on_data
        self._log = log or (lambda m: None)
        self.epoch = 0
        self.state = EpochState.IDLE
        self.counts: Counter = Counter()      # by FrameType
        self.data_frames = 0
        self.data_bytes = 0
        self.resyncs = 0

    def feed(self, data: bytes) -> List[ZenohFrame]:
        """Append bytes, decode every complete frame, drive state + callbacks.
        Trailing partial bytes are retained for the next feed."""
        self._buf += data
        b = self._buf
        out: List[ZenohFrame] = []
        i, n = 0, len(b)
        while i < n:
            tag = b[i]
            t = _TAG_TO_TYPE.get(tag)
            if t is None:
                nxt = _next_tag(b, i + 1)
                self.resyncs += 1
                self._log(f"zenoh: bad tag {tag:#04x}; resync")
                if nxt is None:
                    i = n
                    break
                i = nxt
                continue
            if t is FrameType.DATA:
                if i + 5 > n:
                    break                                   # need the header
                sid = int.from_bytes(b[i + 1:i + 3], "big")
                ln = int.from_bytes(b[i + 3:i + 5], "little")
                if ln == RESERVED_LEN:
                    self._log("zenoh: reserved A7 length; reset")
                    i += 5
                    continue
                if i + 5 + ln > n:
                    break                                   # need the payload
                frame = ZenohFrame(t, sid, bytes(b[i + 5:i + 5 + ln]))
                i += 5 + ln
            else:
                if i + 5 > n:
                    break
                sid = int.from_bytes(b[i + 1:i + 5], "big")
                if sid == 0:
                    self._log("zenoh: zero epoch id; skip")
                    i += 5
                    continue
                frame = ZenohFrame(t, sid, b"")
                i += 5
            out.append(frame)
            self._dispatch(frame)
        del self._buf[:i]
        return out

    def _dispatch(self, f: ZenohFrame) -> None:
        self.counts[f.type] += 1
        if f.type is FrameType.CONNECT:
            self.epoch, self.state = f.epoch, EpochState.CONNECTING
            if self._on_connect:
                self._on_connect(f.epoch)
        elif f.type is FrameType.READY:
            if self.epoch == 0:
                self.epoch = f.epoch       # responder may introduce the epoch
            self.state = EpochState.READY
            if self._on_ready:
                self._on_ready(f.epoch)
        elif f.type is FrameType.CLOSE:
            self.state = EpochState.CLOSED
            if self._on_close:
                self._on_close(f.epoch)
        else:  # DATA
            self.data_frames += 1
            self.data_bytes += len(f.payload)
            if self._on_data:
                self._on_data(f)


# ── EXPERIMENTAL inner zenoh-pico heuristics ─────────────────────────────────
# The robot's zenoh-pico batch encoding was not fully reversed. These scan a DATA
# payload for ASCII that looks like zenoh key expressions / strings. Useful to see
# which topics are flowing before a full zenoh-pico decoder exists. Best-effort.
_PRINTABLE = re.compile(rb"[\x20-\x7e]{3,}")
# key expr: segments of word chars / * / $*, joined by '/', at least one '/'
_KEYEXPR = re.compile(r"^[A-Za-z0-9_\-.*$@]+(?:/[A-Za-z0-9_\-.*$@]+)+$")


def printable_strings(data: bytes, min_len: int = 4) -> List[str]:
    """EXPERIMENTAL: ASCII runs of length >= min_len found in a batch."""
    return [m.group().decode("ascii", "replace")
            for m in _PRINTABLE.finditer(data) if len(m.group()) >= min_len]


def keyexpr_candidates(data: bytes) -> List[str]:
    """EXPERIMENTAL: printable runs that look like zenoh key expressions
    (e.g. 'state/battery', 'cmd/vel', 'mission/request'). Heuristic only."""
    seen: List[str] = []
    for s in printable_strings(data, min_len=3):
        for token in re.split(r"[^\x20-\x7e]+", s):
            token = token.strip()
            if _KEYEXPR.match(token) and token not in seen:
                seen.append(token)
    return seen


def _is_sealed(payload: bytes) -> bool:
    from . import md_ts                            # stdlib-only import (crypto is lazy)
    return md_ts.decode_envelope(payload) is not None


# ── monitor: plug into the client's ch0 on_message ───────────────────────────
class ZenohMonitor:
    """Passive zenoh telemetry monitor. Wire `on_message` into MondoClient (it only
    acts on channel-0 frames whose first byte is an A4-A7 tag). Fully decodes each
    A7 batch with the real zenoh-pico decoder (zenoh_pico.py) to a live table of
    topic → latest value; falls back to the ASCII heuristic for any batch the
    protocol decoder can't parse."""

    def __init__(self, log: Optional[Callable[[str], None]] = None, keep: int = 8):
        self.link = ZenohLink(on_connect=self._on_connect, on_ready=self._on_ready,
                              on_close=self._on_close, on_data=self._on_data, log=log)
        self._log = log or (lambda m: None)
        self.keyexprs: Counter = Counter()        # heuristic fallback tally
        self.recent_batches: deque = deque(maxlen=keep)
        self.frames = 0
        self._pico = zenoh_pico.ZenohPicoDecoder()
        self.topics: dict = {}                    # keyexpr → {value, encoding, kind, n}
        self.decoded_msgs = 0
        self.undecoded_batches = 0
        # optional (keyexpr, payload) -> plaintext|None, e.g. MondoClient.unseal, so
        # MD-TS-sealed telemetry displays decrypted (None = drop the value)
        self.unseal: Optional[Callable[[str, bytes], Optional[bytes]]] = None

    def on_message(self, channel: int, payload: bytes) -> None:
        if channel not in _ZCH or not payload or payload[0] not in ALL_TAGS:
            return
        self.frames += 1
        self.link.feed(payload)

    def _on_connect(self, epoch: int) -> None:
        self._log(f"zenoh: CONNECT epoch={epoch}")

    def _on_ready(self, epoch: int) -> None:
        self._log(f"zenoh: READY epoch={epoch}")

    def _on_close(self, epoch: int) -> None:
        self._log(f"zenoh: CLOSE epoch={epoch}")

    def _on_data(self, f: ZenohFrame) -> None:
        msgs = self._pico.decode_batch(f.payload)
        puts = [m for m in msgs if isinstance(m, (zenoh_pico.Put, zenoh_pico.Del))]
        for m in puts:
            self.decoded_msgs += 1
            t = self.topics.setdefault(m.keyexpr, {"n": 0})
            t["n"] += 1
            t["kind"] = m.kind
            if isinstance(m, zenoh_pico.Put):
                if self.unseal is not None:
                    plain = self.unseal(m.keyexpr, m.payload)
                    m = replace(m, payload=plain) if plain is not None else None
                elif _is_sealed(m.payload):
                    m = None                                  # MD-TS record, no key
                t["value"] = m.value() if m is not None else "<sealed>"
                if m is None:
                    continue
                t["encoding"] = str(m.encoding) if m.encoding else None
            else:
                t["value"] = "<del>"
        if not puts:                              # nothing decoded → ASCII fallback
            self.undecoded_batches += 1
            for ke in keyexpr_candidates(f.payload):
                self.keyexprs[ke] += 1
        self.recent_batches.append((f.epoch, f.payload[:48].hex(), [m.keyexpr for m in puts]))

    def snapshot(self) -> dict:
        topics = [{"keyexpr": k, "value": v.get("value"), "encoding": v.get("encoding"),
                   "kind": v.get("kind"), "n": v["n"]}
                  for k, v in sorted(self.topics.items())]
        return {
            "epoch": self.link.epoch,
            "state": self.link.state.value,
            "frames": {t.name.lower(): self.link.counts.get(t, 0) for t in FrameType},
            "data_frames": self.link.data_frames,
            "data_bytes": self.link.data_bytes,
            "resyncs": self.link.resyncs,
            "decoded_msgs": self.decoded_msgs,
            "topics": topics,
            "keyexprs": self.keyexprs.most_common(16),   # heuristic-only leftovers
        }

    def format_summary(self) -> str:
        s = self.snapshot()
        lines = [
            f"=== Zenoh-over-UCP === epoch={s['epoch']} state={s['state']}",
            "  frames: " + "  ".join(f"{k}={v}" for k, v in s["frames"].items())
            + f"  (resyncs {s['resyncs']})",
            f"  DATA: {s['data_frames']} batches, {s['data_bytes']} B · "
            f"{s['decoded_msgs']} msgs decoded",
        ]
        if s["topics"]:
            lines.append("  topics (decoded):")
            for t in s["topics"]:
                enc = f"  [{t['encoding']}]" if t["encoding"] else ""
                lines.append(f"    {t['keyexpr']} = {t['value']}{enc}  ×{t['n']}")
        if s["keyexprs"]:
            lines.append("  key exprs (heuristic, undecoded batches):")
            lines += [f"    {ke}  ×{c}" for ke, c in s["keyexprs"]]
        if not s["topics"] and not s["keyexprs"]:
            lines.append("  (no telemetry decoded yet)")
        return "\n".join(lines)


# ── outbound: publish zenoh Put/Del over the link ─────────────────────────────
class ZenohPublisher:
    """Send half of the zenoh-over-UCP stack. Opens an epoch (A4 CONNECT) and
    publishes zenoh Put/Del messages as reliable FRAME batches wrapped in A7 DATA.
    `send(payload)` must transmit `payload` on the zenoh-over-UCP link (reliable ch3)
    (e.g. `lambda p: client._t.send(3, p, reliable=True)`).

    The Put bytes are byte-exact to what libmondo_native.so's zenoh-pico emits
    (`_z_push_encode`/`_z_put_encode`). STATIC/UNTESTED: whether a real robot acts
    on a Put after only the A4/A5 epoch — versus also requiring a full zenoh
    INIT/OPEN session — is unconfirmed, and `/cmd/*` payloads are protobuf whose
    schemas aren't recovered here. This produces the wire frames; those two
    questions are what a hardware test must answer."""

    def __init__(self, send: Callable[[bytes], None], epoch: int = 0x42,
                 log: Optional[Callable[[str], None]] = None, transport=None):
        self._send = send
        self._transport = transport                    # for the session handshake recv
        self.epoch = epoch & 0xFFFFFFFF
        self._sn = 0
        self._opened = False
        self._log = log or (lambda m: None)
        self.sent = 0
        self.session_open = False
        self.cookie = b""
        self._zid = os.urandom(16)

    def open(self) -> None:
        if self._opened:
            return
        self._send(encode_connect(self.epoch))         # A4 CONNECT (mdZenohOverUcp epoch)
        self._opened = True
        self._log(f"zenoh pub: epoch {self.epoch} opened (A4)")
        if self._transport is not None:
            self._session_handshake()

    def _session_handshake(self) -> None:
        """Full zenoh unicast handshake over the epoch: InitSyn→InitAck→OpenSyn→OpenAck."""
        from . import zenoh_session as zsx
        import queue
        import time
        cap = self._transport.begin_capture()
        try:
            self._send(encode_data(self.epoch & 0xFFFF, zsx.encode_init_syn(self._zid)))

            def _recv(predicate, timeout=2.0):
                end = time.monotonic() + timeout
                while time.monotonic() < end:
                    try:
                        payload = cap.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    if not payload or payload[0] not in ALL_TAGS:
                        continue
                    for fr in iter_frames(payload):
                        if fr.is_data and zsx.is_transport_msg(fr.payload) and predicate(fr.payload):
                            return fr.payload
                return None

            iack = _recv(zsx.is_init_ack)
            if iack is None:
                self._log("zenoh session: no InitAck (robot may skip the session)")
                return
            self.cookie = zsx.decode_transport(iack).cookie
            self._send(encode_data(self.epoch & 0xFFFF, zsx.encode_open_syn(0, self.cookie)))
            oack = _recv(zsx.is_open_ack)
            if oack is None:
                self._log("zenoh session: no OpenAck")
                return
            self.session_open = True
            self._log(f"zenoh session OPEN (cookie {len(self.cookie)}B)")
        except Exception as e:                          # noqa: BLE001 — never block publishing
            self._log(f"zenoh session handshake error: {e!r}")
        finally:
            self._transport.end_capture()

    def close(self) -> None:
        if self._opened:
            try:
                self._send(encode_close(self.epoch))    # A6 CLOSE
            except Exception:                           # noqa: BLE001
                pass
            self._opened = False

    def _wrap(self, net: bytes) -> bytes:
        sn = self._sn
        self._sn = (self._sn + 1) & 0xFFFFFFFF
        return encode_data(self.epoch & 0xFFFF,
                           zenoh_pico.encode_frame(sn, net, reliable=True))

    def put(self, keyexpr: str, payload, encoding: Optional[int] = None,
            timestamp=None) -> None:
        self.open()
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        net = zenoh_pico.encode_put(keyexpr, bytes(payload), encoding=encoding,
                                    timestamp=timestamp)
        self._send(self._wrap(net))
        self.sent += 1
        self._log(f"zenoh pub: PUT {keyexpr} ({len(payload)} B)")

    def delete(self, keyexpr: str) -> None:
        self.open()
        self._send(self._wrap(zenoh_pico.encode_del(keyexpr)))
        self.sent += 1
        self._log(f"zenoh pub: DEL {keyexpr}")

    def declare_subscriber(self, keyexpr: str, sub_id: int = 1) -> None:
        """Declare a subscriber so the robot routes matching key expressions
        (e.g. a `_rsp` topic) back to us."""
        self.open()
        self._send(self._wrap(zenoh_pico.encode_declare_subscriber(sub_id, keyexpr)))
        self._log(f"zenoh pub: DECLARE subscriber {keyexpr} (id {sub_id})")
