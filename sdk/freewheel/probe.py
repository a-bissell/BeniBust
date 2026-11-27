"""First-contact preflight probe — the layered "does the robot accept it?" doctor.

Walks the protocol stack bottom-up against a live robot and reports, per layer,
PASS / FAIL / WARN / SKIP with the exact point things stop working — so on
hardware day you learn *where* the clean-room model diverges, not just that it
did. It is SAFE by construction: the passive run streams only the locked,
zero-speed control word (no motion is possible), and even the active run never
unlocks — it only completes the zenoh session and, optionally, a read-only
request/response round-trip.

    from freewheel.probe import Probe
    print(Probe("192.168.7.1").run())            # passive: L0–L3
    print(Probe("192.168.7.1", active=True,      # + session, read-only round-trip
                capture_path="beni.fwcap").run()) # also records a .fwcap for the ledger

Layers:
  L0  UCP handshake        ucp:sync → ucp:ack
  L1  RX / channel demux   datagrams flowing, split onto channels 0–3
  L2  zenoh link           A4/A5/A7 framing (robot READY / DATA)
  L3  telemetry decode     zenoh-pico batches decode to topics
  L4  zenoh session        InitSyn→InitAck→OpenSyn→OpenAck      (active)
  L6  request/response     read-only _req → _rsp by seqNum       (active)

Pair the recorded capture with `freewheel.conformance.check_capture()` for a
graded verdict on every clean-room assumption.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .client import MondoClient
from .diagnostics import RxMonitor
from .zenoh import ZenohMonitor

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
_MARK = {PASS: "✓", FAIL: "✗", WARN: "!", SKIP: "·"}

# read-only-looking request topics, preferred for the active round-trip probe
_SAFE_REQ_HINTS = ("ping", "status", "info", "version", "state", "query", "get", "list")


@dataclass
class Step:
    layer: str
    name: str
    status: str
    detail: str = ""

    def __str__(self) -> str:
        return f"  [{_MARK[self.status]}] {self.layer:3} {self.name:22} {self.status}  {self.detail}"


@dataclass
class ProbeReport:
    steps: List[Step] = field(default_factory=list)
    conformance: object = None          # optional conformance.Report
    capture_path: Optional[str] = None

    @property
    def ok(self) -> bool:
        return all(s.status != FAIL for s in self.steps)

    @property
    def reached(self) -> str:
        passed = [s.layer for s in self.steps if s.status == PASS]
        return passed[-1] if passed else "none"

    def __str__(self) -> str:
        head = "=== Freewheel preflight ===  " + ("GO" if self.ok else "NO-GO") \
               + f"  (reached {self.reached})"
        lines = [head] + [str(s) for s in self.steps]
        if self.capture_path:
            lines.append(f"  capture: {self.capture_path}")
        if self.conformance is not None:
            lines.append("")
            lines.append(str(self.conformance))
        return "\n".join(lines)


class Probe:
    def __init__(self, host: str, port: int = 9007, *, active: bool = False,
                 observe_s: float = 6.0, req_topic: Optional[str] = None,
                 capture_path: Optional[str] = None,
                 log: Optional[Callable[[str], None]] = None):
        self.host = host
        self.port = port
        self.active = active
        self.observe_s = observe_s
        self.req_topic = req_topic
        self.capture_path = capture_path
        self._log = log or (lambda m: None)

    def run(self) -> ProbeReport:
        rep = ProbeReport(capture_path=self.capture_path)
        rx = RxMonitor()
        zmon = ZenohMonitor(log=self._log)
        cap = None
        if self.capture_path:
            from .capture import Capture
            cap = Capture(self.capture_path, host=self.host, port=self.port,
                          note="freewheel preflight probe")

        def on_raw(d):
            rx.on_raw(d)
            if cap:
                cap.record_rx(d)

        def on_message(ch, payload):
            rx.on_message(ch, payload)
            zmon.on_message(ch, payload)

        client = MondoClient(self.host, self.port, on_message=on_message, on_raw=on_raw,
                             on_send=(cap.record_tx if cap else None),
                             listen_only=not self.active, log=self._log)

        # L0 — UCP handshake
        try:
            client.connect()
            rep.steps.append(Step("L0", "UCP handshake", PASS,
                                  f"ucp:ack from {self.host}:{self.port}"))
        except TimeoutError as e:
            rep.steps.append(Step("L0", "UCP handshake", FAIL, str(e)))
            if cap:
                cap.close()
            return rep

        l4_step = None
        try:
            # L4 (active) — open the zenoh session FIRST: on a real robot telemetry
            # and /cmd handling are gated on it, so we must open it before observing.
            if self.active:
                l4_step = self._open_session(client)

            time.sleep(self.observe_s)                       # let RX accumulate

            # L1 — RX flowing + channel demux
            if rx.raw_count > 0:
                chans = ", ".join(f"ch{c}×{rx.ch[c]['count']}" for c in sorted(rx.ch))
                rate = rx.raw_bytes / max(self.observe_s, 1e-6) / 1024
                rep.steps.append(Step("L1", "RX / channel demux", PASS,
                                      f"{rx.raw_count} datagrams ({rate:.1f} KiB/s); {chans or 'unparsed'}"))
            else:
                rep.steps.append(Step("L1", "RX / channel demux", FAIL,
                                      "no inbound datagrams (robot not streaming to us)"))

            # L2 — zenoh-over-UCP link
            snap = zmon.snapshot()
            fr = snap["frames"]
            link_live = fr.get("ready") or fr.get("data") or snap["data_frames"]
            rep.steps.append(Step("L2", "zenoh link (A4/A5/A7)",
                                  PASS if link_live else WARN,
                                  f"ready={fr.get('ready',0)} data={snap['data_frames']} "
                                  f"state={snap['state']}"
                                  + ("" if link_live else " — no link frames (session-gated?)")))

            # L3 — telemetry decode
            if snap["decoded_msgs"]:
                sample = ", ".join(t["keyexpr"] for t in snap["topics"][:4])
                rep.steps.append(Step("L3", "telemetry decode",
                                      PASS if snap["decoded_msgs"] else WARN,
                                      f"{snap['decoded_msgs']} msgs, {len(snap['topics'])} topics: {sample}"))
            else:
                undec = snap.get("keyexprs")
                rep.steps.append(Step("L3", "telemetry decode", WARN,
                                      f"0 decoded; {len(undec)} heuristic keyexprs"
                                      if undec else "no telemetry decoded"))

            if self.active:
                if l4_step is not None:
                    rep.steps.append(l4_step)                # L4 in layer order
                self._crypto_mode(client, rep)               # L5 — secure_v2?
                self._request_roundtrip(client, rep)         # L6
        finally:
            try:
                client.close()
            finally:
                if cap:
                    cap.close()

        if cap:
            from . import conformance
            try:
                rep.conformance = conformance.check_capture(self.capture_path)
            except Exception as e:                           # noqa: BLE001
                self._log(f"conformance grading failed: {e!r}")
        return rep

    def _open_session(self, client: MondoClient) -> Step:
        # opening the publisher runs the InitSyn→InitAck→OpenSyn→OpenAck handshake
        pub = client.publisher()
        pub.open()
        time.sleep(0.3)
        if pub.session_open:
            return Step("L4", "zenoh session", PASS, f"OPEN (cookie {len(pub.cookie)}B)")
        return Step("L4", "zenoh session", WARN,
                    "no InitAck/OpenAck — robot may not run a unicast session")

    def _crypto_mode(self, client: MondoClient, rep: ProbeReport) -> None:
        # L5 — control-bus crypto mode (v1.0.85+): MD-TS negotiation + get_crypto_info.
        from .md_ts import MdTsError, PAIRING_HINT
        try:
            state = client.secure(timeout=2.0)
        except MdTsError as e:
            rep.steps.append(Step("L5", "crypto mode", FAIL, f"MD-TS rejected: {e}"))
            return
        try:
            info = client.crypto_info(timeout=1.5)
        except Exception as e:                               # noqa: BLE001
            rep.steps.append(Step("L5", "crypto mode", WARN, f"security={state}; get_crypto_info: {e!r}"))
            return
        if state == "md-ts":
            rep.steps.append(Step("L5", "crypto mode", PASS,
                                  f"MD-TS session established; get_crypto_info={info}"))
        elif info is None:
            rep.steps.append(Step("L5", "crypto mode", WARN,
                                  "plaintext and no get_crypto_info response: either legacy/plaintext "
                                  "control, or an encrypted robot ignoring us (" + PAIRING_HINT + ")"))
        elif info.get("isEncrypted"):
            rep.steps.append(Step("L5", "crypto mode", FAIL,
                                  f"robot requires ENCRYPTED control ({info}) but no MD-TS session: "
                                  + PAIRING_HINT))
        else:
            rep.steps.append(Step("L5", "crypto mode", PASS,
                                  f"plaintext control OK (isEncrypted=0; {info})"))

    def _request_roundtrip(self, client: MondoClient, rep: ProbeReport) -> None:
        # L6 — read-only request/response round-trip
        topic = self.req_topic or self._pick_safe_req()
        if topic is None:
            rep.steps.append(Step("L6", "request/response", SKIP,
                                  "no read-only _req topic found; pass req_topic= to test"))
            return
        try:
            result = client.request(topic, timeout=2.5)
        except Exception as e:                               # noqa: BLE001
            rep.steps.append(Step("L6", "request/response", FAIL, f"{topic}: {e!r}"))
            return
        if result is not None:
            rep.steps.append(Step("L6", "request/response", PASS,
                                  f"{topic} → seqNum={result['seqNum']} data={result['data']}"))
        else:
            rep.steps.append(Step("L6", "request/response", WARN,
                                  f"{topic}: no response (timeout; attestation or wrong topic?)"))

    @staticmethod
    def _pick_safe_req() -> Optional[str]:
        """Pick a read-only-looking `*_req` topic from the recovered schemas, so the
        active probe never sends a state-changing command."""
        from . import cmd_proto
        candidates = []
        for topic in cmd_proto.all_request_topics():
            low = topic.lower()
            if any(h in low for h in _SAFE_REQ_HINTS):
                candidates.append(topic)
        candidates.sort(key=lambda t: (0 if "ping" in t.lower() else 1, len(t)))
        return candidates[0] if candidates else None
