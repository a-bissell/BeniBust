"""Passive RX diagnostics for first-contact testing.

Tallies everything the robot sends back — per-channel counts/rates/sizes, a
first-byte histogram (to spot the ch0 0xA7=zenoh / 0xAE=drop demux), and a sample
hexdump — without ever commanding motion. Pair with MondoClient(listen_only=True).
"""
from __future__ import annotations

import threading
import time
from collections import Counter, defaultdict

CHANNEL_NAMES = {0: "msg/zenoh", 1: "video(HEVC)", 2: "audio(Opus)", 3: "dds"}


class RxMonitor:
    """Thread-safe accumulator for inbound UCP frames and raw datagrams."""

    def __init__(self, sample_hex_bytes: int = 32):
        self._lock = threading.Lock()
        self._sample_n = sample_hex_bytes
        self._t0 = time.monotonic()
        self.raw_count = 0
        self.raw_bytes = 0
        self.parsed_count = 0
        # per-channel: count, bytes, min/max len, first-byte histogram, last sample
        self.ch = defaultdict(lambda: {
            "count": 0, "bytes": 0, "min": None, "max": 0,
            "first_bytes": Counter(), "sample": b"",
        })

    # wire these into the transport / client
    def on_raw(self, data: bytes) -> None:
        with self._lock:
            self.raw_count += 1
            self.raw_bytes += len(data)

    def on_message(self, channel: int, payload: bytes) -> None:
        with self._lock:
            self.parsed_count += 1
            c = self.ch[channel]
            c["count"] += 1
            c["bytes"] += len(payload)
            c["max"] = max(c["max"], len(payload))
            c["min"] = len(payload) if c["min"] is None else min(c["min"], len(payload))
            if payload:
                c["first_bytes"][payload[0]] += 1
                c["sample"] = payload[:self._sample_n]

    def format_summary(self) -> str:
        with self._lock:
            dt = max(1e-6, time.monotonic() - self._t0)
            lines = [
                f"=== RX summary @ {dt:5.1f}s ===",
                f"  datagrams: {self.raw_count} ({self.raw_bytes} B, "
                f"{self.raw_bytes / dt / 1024:.1f} KiB/s) · parsed UCP frames: {self.parsed_count}",
            ]
            if not self.ch:
                lines.append("  (no parsed per-channel frames yet)")
            for ch in sorted(self.ch):
                c = self.ch[ch]
                name = CHANNEL_NAMES.get(ch, "?")
                fb = ", ".join(f"0x{b:02x}×{n}" for b, n in c["first_bytes"].most_common(4))
                lines.append(
                    f"  ch{ch} {name:12} {c['count']:5d} frm  "
                    f"{c['count'] / dt:5.1f}/s  len {c['min']}..{c['max']}  first=[{fb}]"
                )
                if c["sample"]:
                    lines.append(f"       sample: {c['sample'].hex()}")
            return "\n".join(lines)

    def run_printer(self, stop: threading.Event, every: float = 2.0,
                    log=print) -> None:
        """Print a summary every `every` seconds until `stop` is set."""
        while not stop.wait(every):
            log(self.format_summary())
