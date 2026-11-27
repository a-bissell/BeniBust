"""UCP reliable-UDP transport (clean-room, from static RE of libmondo_native.so).

Reference: native-analysis/README.md §3a, control-packet.md §4, and the
community cross-check (native-analysis/community-crosscheck.md §2). Counter
semantics follow the community SDK notes, which report hardware testing on an
LZ110. They are pinned by sdk/tests/test_crosscheck.py.

Wire (all little-endian):
  12-byte header: u16 flags, u16 una, u16 sn, u16 len, u32 ts(us, monotonic)
    flags low byte = 0x51 magic/ver; bit8 reliable; bit9 more-fragments;
    bits10-11 channel; bit12 SACK trailer present ("heartbeat" frames).
  len = total segment length (header + payload [+ 11-byte SACK trailer]).
  SACK trailer: 0x05, u16 rcv_nxt, u32 bitmap_lo, u32 bitmap_hi. Bit (d-1) of
    lo / (d-33) of hi marks sn = rcv_nxt + d (d = 1..64) received out of order.
  One datagram may carry several concatenated segments.

Counters (per session, reset on connect):
  una     = rcv_nxt, the NEXT reliable sn we expect from the robot (cumulative ack).
  sn      = reliable: snd_nxt, starting at 0, one per fragment.
            unreliable: its own per-session counter, starting at 0.

Channels: 0 control (joystick heartbeat, "UCP:" RTT probes, unreliable zenoh
pushes), 1 video, 2 audio, 3 reliable zenoh-over-UCP (A4-A7). The robot treats
EVERY unreliable 8-byte ch0 payload as an RcJoystick word, so `send()` refuses
one unless it comes from `send_heartbeat()`.

Handshake: send b"ucp:sync", expect b"ucp:ack". Teardown: b"ucp:leav".
"""
from __future__ import annotations

import socket
import struct
import threading
import time
from collections import OrderedDict
from typing import Callable, Optional

MAGIC = 0x51                 # flags low byte (magic 5 / version 1)
FLAG_RELIABLE = 0x0100       # header bit 8
FLAG_MORE_FRAG = 0x0200      # header bit 9
FLAG_HEARTBEAT = 0x1000      # header bit 12: SACK trailer present
FLAG_SACK = FLAG_HEARTBEAT
HEADER = struct.Struct("<HHHHI")   # flags, una, sn, len, ts
SACK = struct.Struct("<BHII")      # 0x05, rcv_nxt, bitmap_lo, bitmap_hi
SACK_MAGIC = 0x05
HEARTBEAT_TRAILER = struct.pack("<BHII", SACK_MAGIC, 0, 0, 0)  # empty SACK (length reference)

CH_CONTROL = 0
CH_VIDEO = 1
CH_AUDIO = 2
CH_ZENOH = 3
ZENOH_CHANNELS = (CH_CONTROL, CH_ZENOH)   # zenoh link frames arrive on either

MSS = 1460
MAX_PAYLOAD = MSS - HEADER.size - SACK.size  # 1437: largest fragment payload
MAX_VIDEO_AU_BYTES = 2 * 1024 * 1024
JOYSTICK_PAYLOAD_LEN = 8

RTO_S = 0.15                 # observed floor (rto = max(0.15, min(0.5, 3*rtt + 0.12)))
RTO_MAX_S = 2.0
MAX_RETRIES = 40
RX_OOO_WINDOW = 512          # accept reliable segments up to this far ahead

SYNC = b"ucp:sync"
ACK = b"ucp:ack"
LEAVE = b"ucp:leav"

RX_WATCHDOG_S = 3.5          # native force-disconnects after this with no RX
_RX_TICK_S = 0.05            # rx loop wake-up for retransmit service


def _now_us() -> int:
    return (time.monotonic_ns() // 1000) & 0xFFFFFFFF


def seq_diff(a: int, b: int) -> int:
    """Signed 16-bit (a - b) in [-32768, 32767]."""
    d = (a - b) & 0xFFFF
    return d - 0x10000 if d >= 0x8000 else d


def decode_segments(datagram: bytes) -> list:
    """Parse one datagram into a list of segment dicts (stops at the first malformed one).

    Each dict: channel, reliable, more, una, sn, ts, payload, sack (None or
    (rcv_nxt, bitmap_lo, bitmap_hi))."""
    out, off, total = [], 0, len(datagram)
    while off + HEADER.size <= total:
        flags, una, sn, length, ts = HEADER.unpack_from(datagram, off)
        if (flags & 0xFF) != MAGIC or length < HEADER.size or off + length > total:
            break
        end = off + length
        sack = None
        if flags & FLAG_SACK:
            if length < HEADER.size + SACK.size:
                break
            magic, rn, lo, hi = SACK.unpack_from(datagram, end - SACK.size)
            sack = (rn, lo, hi) if magic == SACK_MAGIC else None
            end -= SACK.size
        out.append({"channel": (flags >> 10) & 0x3, "reliable": bool(flags & FLAG_RELIABLE),
                    "more": bool(flags & FLAG_MORE_FRAG), "una": una, "sn": sn, "ts": ts,
                    "payload": bytes(datagram[off + HEADER.size:end]), "sack": sack})
        off += length
    return out


def encode_segment(channel: int, payload: bytes, *, reliable: bool, more: bool,
                   una: int, sn: int, sack=None, ts: Optional[int] = None) -> bytes:
    """Encode one segment. `sack` is None or (rcv_nxt, bitmap_lo, bitmap_hi)."""
    flags = (MAGIC | ((channel & 0x3) << 10) | (FLAG_RELIABLE if reliable else 0)
             | (FLAG_MORE_FRAG if more else 0) | (FLAG_SACK if sack is not None else 0))
    trailer = b"" if sack is None else SACK.pack(SACK_MAGIC, sack[0] & 0xFFFF,
                                                  sack[1] & 0xFFFFFFFF, sack[2] & 0xFFFFFFFF)
    total = HEADER.size + len(payload) + len(trailer)
    return HEADER.pack(flags, una & 0xFFFF, sn & 0xFFFF, total & 0xFFFF,
                       (_now_us() if ts is None else ts) & 0xFFFFFFFF) + bytes(payload) + trailer


class UcpTransport:
    """UCP client: handshake, ARQ (reliable TX window + retransmit, in-order RX
    with SACK), fragmentation/reassembly, and an RX dispatch thread.

    `on_message(channel, payload)` receives complete messages: reliable ones in
    order and reassembled, unreliable ones as they arrive (SACK trailer stripped).
    """

    def __init__(self, host: str, port: int = 9007,
                 on_message: Optional[Callable[[int, bytes], None]] = None,
                 on_raw: Optional[Callable[[bytes], None]] = None,
                 on_send: Optional[Callable[[bytes], None]] = None,
                 log: Optional[Callable[[str], None]] = None):
        self.host = host
        self.port = port
        self.on_message = on_message            # (channel, payload) for complete messages
        self.on_raw = on_raw                    # (datagram) for EVERY inbound datagram
        self.on_send = on_send                  # (datagram) for EVERY outbound datagram (tap)
        self._log = log or (lambda m: None)
        self._sock: Optional[socket.socket] = None
        self._rx_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()
        self._last_rx = 0.0
        self._last_watchdog_log = 0.0
        self.connected = False
        self.link_dead = False                  # a reliable segment exceeded MAX_RETRIES
        # When True, every inbound reliable segment is acked at once with a
        # heartbeat carrying the last heartbeat payload (ack-only resend).
        self.auto_ack = True
        self._capture = None                    # Optional[queue.Queue] for zenoh frames during handshake
        self.reset_session()

    def reset_session(self) -> None:
        """Reset ARQ counters and buffers (`ucp_set_conn_state(0)` equivalent)."""
        with self._lock:
            self.snd_nxt = 0                    # next reliable sn we send
            self.rcv_nxt = 0                    # next reliable sn we expect (= una we send)
            self.unrel_sn = 0                   # unreliable sn counter
            self._tx_window: "OrderedDict[int, list]" = OrderedDict()  # sn -> [ch, payload, more, last_ts, retries]
            self._rx_ooo: dict = {}             # sn -> segment dict
            self._reasm: dict = {c: bytearray() for c in range(4)}
            self._video_buf = bytearray()       # unreliable CH_VIDEO fragment buffer
            self._video_next_sn: Optional[int] = None
            self._video_dropping = False
            self._hb_payload: Optional[bytes] = None
            self.link_dead = False

    # -- lifecycle ---------------------------------------------------------
    def connect(self, attempts: int = 3, timeout: float = 0.3) -> None:
        """Open the socket and perform the ucp:sync/ucp:ack handshake."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((self.host, self.port))       # kernel filters RX to this peer
        s.settimeout(timeout)
        self._sock = s
        self.reset_session()
        for i in range(attempts):
            s.send(SYNC)
            self._tap(SYNC)                     # tap the handshake so captures are lossless
            try:
                while True:
                    data = s.recv(2048)
                    self._raw(data)
                    if data[:7] == ACK:         # app checks only first 7 bytes
                        self.connected = True
                        self._last_rx = time.monotonic()
                        self._log(f"handshake ok (attempt {i + 1})")
                        self._start_rx()
                        return
            except socket.timeout:
                continue
        s.close()
        self._sock = None
        raise TimeoutError(f"no ucp:ack from {self.host}:{self.port} after {attempts} attempts")

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.send(LEAVE)
            except OSError:
                pass
        self._running = False
        self.connected = False
        if self._rx_thread is not None:
            self._rx_thread.join(timeout=1.0)
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    # -- helpers -------------------------------------------------------------
    def _tap(self, datagram: bytes) -> None:
        if self.on_send is not None:
            try:
                self.on_send(datagram)
            except Exception as e:              # never let a tap kill tx
                self._log(f"on_send error: {e!r}")

    def _raw(self, datagram: bytes) -> None:
        if self.on_raw is not None:
            try:
                self.on_raw(bytes(datagram))
            except Exception as e:              # noqa: BLE001
                self._log(f"on_raw error: {e!r}")

    def _xmit(self, datagram: bytes) -> None:
        if self._sock is None:
            raise RuntimeError("not connected")
        self._tap(datagram)
        self._sock.send(datagram)

    def _sack(self, always: bool = False):
        """SACK tuple for the current RX state, or None when there is nothing to report."""
        if not self._rx_ooo and not always:
            return None
        lo = hi = 0
        for sn in self._rx_ooo:
            d = seq_diff(sn, self.rcv_nxt)
            if 1 <= d <= 32:
                lo |= 1 << (d - 1)
            elif 33 <= d <= 64:
                hi |= 1 << (d - 33)
        return (self.rcv_nxt, lo, hi)

    # -- tx ----------------------------------------------------------------
    def send(self, channel: int, payload: bytes, *, reliable: bool = False,
             heartbeat: bool = False, _joystick: bool = False) -> None:
        """Send `payload` on `channel` (0..3), fragmenting above MAX_PAYLOAD.

        reliable: assigned snd_nxt per fragment, kept until acked, retransmitted.
        heartbeat: always attach a SACK trailer (flags 0x1051 on ch0)."""
        payload = bytes(payload)
        if (channel == CH_CONTROL and not reliable and len(payload) == JOYSTICK_PAYLOAD_LEN
                and not _joystick):
            raise ValueError("refusing an 8-byte unreliable ch0 payload: the robot reads it as "
                             "a joystick word (use send_heartbeat)")
        chunks = [payload[i:i + MAX_PAYLOAD] for i in range(0, max(1, len(payload)), MAX_PAYLOAD)]
        with self._lock:
            now = time.monotonic()
            for idx, chunk in enumerate(chunks):
                more = idx < len(chunks) - 1
                if reliable:
                    sn = self.snd_nxt
                    self.snd_nxt = (self.snd_nxt + 1) & 0xFFFF
                    self._tx_window[sn] = [channel, chunk, more, now, 0]
                else:
                    sn = self.unrel_sn
                    self.unrel_sn = (self.unrel_sn + 1) & 0xFFFF
                self._xmit(encode_segment(channel, chunk, reliable=reliable, more=more,
                                          una=self.rcv_nxt, sn=sn,
                                          sack=self._sack(always=heartbeat)))

    def send_heartbeat(self, payload: bytes) -> None:
        """Channel-0 unreliable frame + SACK (flags 0x1051) — the control-word carrier (50 Hz)."""
        with self._lock:
            self._hb_payload = bytes(payload)
            self.send(CH_CONTROL, payload, reliable=False, heartbeat=True, _joystick=True)

    def send_ack(self) -> None:
        """Ack-only: re-send the last heartbeat payload with the current una + SACK."""
        with self._lock:
            if self._hb_payload is not None and self._sock is not None:
                self.send(CH_CONTROL, self._hb_payload, heartbeat=True, _joystick=True)

    def service(self) -> None:
        """Retransmit unacked reliable segments (exponential backoff, current una/SACK)."""
        with self._lock:
            if self._sock is None:
                return
            now = time.monotonic()
            for sn, ent in list(self._tx_window.items()):
                ch, chunk, more, last, retries = ent
                if retries >= MAX_RETRIES:
                    if not self.link_dead:
                        self._log(f"reliable sn {sn} unacked after {MAX_RETRIES} retries: link dead")
                    self.link_dead = True
                    continue
                if now - last >= min(RTO_MAX_S, RTO_S * (1.5 ** min(retries, 6))):
                    ent[3], ent[4] = now, retries + 1
                    self._xmit(encode_segment(ch, chunk, reliable=True, more=more,
                                              una=self.rcv_nxt, sn=sn, sack=self._sack()))

    @property
    def unacked(self) -> int:
        with self._lock:
            return len(self._tx_window)

    # -- handshake capture: temporarily divert inbound zenoh frames to a queue ----
    def begin_capture(self):
        import queue
        self._capture = queue.Queue()
        return self._capture

    def end_capture(self) -> None:
        self._capture = None

    # -- rx ----------------------------------------------------------------
    def _start_rx(self) -> None:
        self._running = True
        self._rx_thread = threading.Thread(target=self._rx_loop, name="ucp-rx", daemon=True)
        self._rx_thread.start()

    def _process_acks(self, una: int, sack) -> None:
        for sn in list(self._tx_window):
            if seq_diff(sn, una) < 0:
                del self._tx_window[sn]
        if sack is None:
            return
        rn, lo, hi = sack
        for sn in list(self._tx_window):
            d = seq_diff(sn, rn)
            if d < 0 or (1 <= d <= 32 and lo & (1 << (d - 1))) or (33 <= d <= 64 and hi & (1 << (d - 33))):
                del self._tx_window[sn]

    def _deliver(self, channel: int, payload: bytes) -> None:
        if not payload:
            return
        if self._capture is not None and channel in ZENOH_CHANNELS and payload[0] in _ZTAGS:
            try:
                self._capture.put_nowait(bytes(payload))
            except Exception:  # noqa: BLE001
                pass
            return
        if self.on_message is not None:
            try:
                self.on_message(channel, bytes(payload))
            except Exception as e:              # never let a callback kill RX
                self._log(f"on_message error: {e!r}")

    def _deliver_reliable(self, seg: dict) -> list:
        """Reassemble one in-order reliable fragment; return completed messages."""
        buf = self._reasm.setdefault(seg["channel"], bytearray())
        if seg["channel"] == CH_VIDEO and len(buf) + len(seg["payload"]) > MAX_VIDEO_AU_BYTES:
            buf.clear()
        else:
            buf.extend(seg["payload"])
        if seg["more"]:
            return []
        done = bytes(buf)
        buf.clear()
        return [(seg["channel"], done)] if done else []

    def _deliver_unreliable_video(self, seg: dict) -> list:
        """Reassemble unreliable CH_VIDEO fragments, dropping any AU with a sequence gap."""
        gap = (self._video_next_sn is not None and seg["sn"] != self._video_next_sn
               and bool(self._video_buf))
        self._video_next_sn = (seg["sn"] + 1) & 0xFFFF
        if gap:
            self._video_buf.clear()
            self._video_dropping = True
        if self._video_dropping:
            if not seg["more"]:
                self._video_dropping = False
            return []
        if len(self._video_buf) + len(seg["payload"]) <= MAX_VIDEO_AU_BYTES:
            self._video_buf.extend(seg["payload"])
        else:
            self._video_buf.clear()
        if seg["more"]:
            return []
        done = bytes(self._video_buf)
        self._video_buf.clear()
        return [(CH_VIDEO, done)] if done else []

    def handle_datagram(self, data: bytes) -> None:
        """Process one inbound UCP datagram (public for tests and simulators)."""
        ready: list = []
        need_ack = False
        with self._lock:
            for seg in decode_segments(data):
                self._process_acks(seg["una"], seg["sack"])
                if seg["reliable"]:
                    need_ack = True
                    d = seq_diff(seg["sn"], self.rcv_nxt)
                    if d == 0:
                        self.rcv_nxt = (self.rcv_nxt + 1) & 0xFFFF
                        ready += self._deliver_reliable(seg)
                        while self.rcv_nxt in self._rx_ooo:
                            nxt = self._rx_ooo.pop(self.rcv_nxt)
                            self.rcv_nxt = (self.rcv_nxt + 1) & 0xFFFF
                            ready += self._deliver_reliable(nxt)
                    elif 0 < d <= RX_OOO_WINDOW:
                        self._rx_ooo[seg["sn"]] = seg
                    # d < 0: duplicate of something already delivered — just re-ack
                elif seg["channel"] == CH_VIDEO:
                    ready += self._deliver_unreliable_video(seg)
                else:
                    ready.append((seg["channel"], seg["payload"]))
        for ch, payload in ready:                # callbacks outside the lock
            self._deliver(ch, payload)
        if need_ack and self.auto_ack:
            try:
                self.send_ack()
            except OSError:
                pass

    def _rx_loop(self) -> None:
        assert self._sock is not None
        self._sock.settimeout(_RX_TICK_S)
        while self._running:
            try:
                data = self._sock.recv(2048)
            except socket.timeout:
                data = None
            except OSError:
                if self._running:
                    self.link_dead = True
                break
            now = time.monotonic()
            if data is None:
                if now - self._last_rx > RX_WATCHDOG_S and now - self._last_watchdog_log > RX_WATCHDOG_S:
                    self._log("RX watchdog: no data > 3.5s (robot likely dropped us)")
                    self._last_watchdog_log = now
            else:
                self._last_rx = now
                self._raw(data)
                if data in (ACK, SYNC):
                    pass
                elif data[:8] == LEAVE:
                    self._log("peer sent ucp:leav")
                    self.connected = False
                elif len(data) >= HEADER.size and data[0] == MAGIC:
                    self.handle_datagram(data)
            try:
                self.service()
            except OSError:
                break


_ZTAGS = frozenset({0xA4, 0xA5, 0xA6, 0xA7})
