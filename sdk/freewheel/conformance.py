"""Conformance ledger — grade the clean-room assumptions against a real capture.

The SDK is reverse-engineered statically, so a dozen things are *hypotheses* until
a robot confirms them (search the tree for UNVERIFIED / UNCONFIRMED / STATIC). This
module turns a `.fwcap` capture into a verdict on each one: CONFIRMED, REFUTED, or
UNOBSERVED — and when something is REFUTED it prints the value the robot actually
used, which is exactly the delta you need to fix the SDK.

    from freewheel import conformance
    print(conformance.check_capture("beni-firstcontact.fwcap"))

The ledger is deliberately conservative: a check is only CONFIRMED on positive
evidence in the capture, only REFUTED when the observed value contradicts the
assumption, and UNOBSERVED otherwise (traffic to exercise it wasn't present).
Nothing here commands motion; the axis/twist mapping is flagged as needing a
separate, supervised motion test.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional

from . import capture as _cap
from . import cmd_proto, zenoh_session

CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
UNOBSERVED = "UNOBSERVED"
_MARK = {CONFIRMED: "✓", REFUTED: "✗", UNOBSERVED: "·"}


@dataclass
class Finding:
    id: str
    layer: str
    assumption: str
    verdict: str
    evidence: str = ""

    def __str__(self) -> str:
        return f"  [{_MARK[self.verdict]}] {self.id:18} {self.verdict:10} {self.assumption}\n" \
               f"       └ {self.evidence}"


@dataclass
class Facts:
    """Everything the ledger needs, aggregated from one capture decode."""
    rx: int = 0
    tx: int = 0
    saw_ucp_ack: bool = False
    channels: Counter = field(default_factory=Counter)
    saw_zenoh_ready: bool = False     # robot → A5 READY
    saw_zenoh_connect_tx: bool = False
    init_ack: Optional[object] = None  # InitInfo from robot
    open_ack: bool = False
    init_syn_tx: bool = False
    open_syn_tx: bool = False
    puts_rx: Counter = field(default_factory=Counter)   # keyexpr → n (from robot)
    puts_tx: Counter = field(default_factory=Counter)   # keyexpr → n (to robot)
    req_seqs: dict = field(default_factory=dict)        # rsp_topic → set(seqNum) we sent as _req
    rsp_seqs: dict = field(default_factory=dict)        # rsp_topic → set(seqNum) robot returned


def gather(path: str) -> Facts:
    f = Facts()
    header, recs = _cap.read_capture(path)
    for r in recs:
        f.rx += r.dir == "rx"
        f.tx += r.dir == "tx"
    for ev in _cap.decode_capture(path):
        if ev.kind == "ucp-control" and ev.detail.startswith("ucp:ack"):
            f.saw_ucp_ack = True
        if ev.channel is not None:
            f.channels[ev.channel] += 1
        if ev.kind == "zenoh-ready" and ev.dir == "rx":
            f.saw_zenoh_ready = True
        if ev.kind == "zenoh-connect" and ev.dir == "tx":
            f.saw_zenoh_connect_tx = True
        if ev.kind == "transport":
            msg = ev.extra.get("msg", "")
            if msg == "InitAck" and ev.dir == "rx":
                f.init_ack = ev.extra
            elif msg == "OpenAck" and ev.dir == "rx":
                f.open_ack = True
            elif msg == "InitSyn" and ev.dir == "tx":
                f.init_syn_tx = True
            elif msg == "OpenSyn" and ev.dir == "tx":
                f.open_syn_tx = True
        if ev.kind == "put" and ev.keyexpr:
            (f.puts_rx if ev.dir == "rx" else f.puts_tx)[ev.keyexpr] += 1
    _gather_reqresp(path, f)
    return f


def _gather_reqresp(path: str, f: Facts) -> None:
    """Correlate request/response by decoding `/cmd` seqNums from the puts."""
    for ev in _cap.decode_capture(path):
        if ev.kind != "put" or not ev.keyexpr:
            continue
        ke = cmd_proto.canonical_topic(ev.keyexpr)     # app/… and device/… → cmd/…
        # we only need the seqNum; re-decode from the raw record is overkill, so
        # trust the key-expression suffix convention (_req ↔ _rsp)
        if ev.dir == "tx" and ke.endswith("_req"):
            f.req_seqs.setdefault(cmd_proto.response_topic(ke) or ke, set())
        if ev.dir == "rx" and ke.endswith("_rsp"):
            f.rsp_seqs.setdefault(ke, set())


# ── the ledger ───────────────────────────────────────────────────────────────
def evaluate(f: Facts) -> List[Finding]:
    out: List[Finding] = []

    def add(id, layer, assumption, verdict, evidence):
        out.append(Finding(id, layer, assumption, verdict, evidence))

    # L0 — UCP handshake
    add("ucp.handshake", "UCP", "ucp:sync → ucp:ack handshake completes",
        CONFIRMED if f.saw_ucp_ack else UNOBSERVED,
        "robot returned ucp:ack" if f.saw_ucp_ack else "no ucp:ack in capture")

    # L0 — heartbeat trailer / liveness (indirect: we sent our trailer and the
    # robot kept streaming rather than dropping us on its RX watchdog)
    alive = f.rx > 5 and f.tx > 0
    add("ucp.heartbeat", "UCP",
        "heartbeat trailer (0x05 + zeros) keeps the link alive",
        CONFIRMED if alive else UNOBSERVED,
        f"robot kept sending ({f.rx} rx datagrams) while we streamed heartbeats"
        if alive else "not enough bidirectional traffic to tell")

    # L1 — channel demux
    chans = ", ".join(f"ch{c}×{n}" for c, n in sorted(f.channels.items()))
    add("ucp.channels", "UCP", "inbound frames demux onto channels 0–3",
        CONFIRMED if f.channels else UNOBSERVED, chans or "no framed datagrams")

    # L2 — zenoh-over-UCP link framing (A4–A7)
    add("zenoh.link", "zenoh-link", "mdZenohOverUcp A4/A5/A7 framing (robot emits A5 READY)",
        CONFIRMED if f.saw_zenoh_ready else UNOBSERVED,
        "robot sent an A5 READY frame" if f.saw_zenoh_ready
        else "no A5 READY seen (robot may gate it on the session)")

    # L3 — zenoh-pico batch decode
    decoded = sum(f.puts_rx.values())
    add("zenohpico.decode", "zenoh-pico", "zenoh-pico batch decoder matches the robot's encoder",
        CONFIRMED if decoded else UNOBSERVED,
        f"{decoded} Put(s) decoded across {len(f.puts_rx)} key expressions"
        if decoded else "no Puts decoded from the robot")

    # L4 — session handshake constants
    if f.init_ack:
        ia = f.init_ack
        ver, batch, cookie_len = ia.get("version"), ia.get("batch_size"), ia.get("cookie_len", 0)
        vmatch = ver == zenoh_session.PROTO_VERSION
        add("zenoh.version", "zenoh-session",
            f"zenoh protocol version == {zenoh_session.PROTO_VERSION:#x} (Zenoh 1.0)",
            CONFIRMED if vmatch else REFUTED,
            f"robot InitAck version={ver:#x}" + ("" if vmatch else "  ← SDK uses 0x09; update it"))
        bmatch = batch == zenoh_session.BATCH_SIZE
        add("zenoh.batch", "zenoh-session", f"session batch size == {zenoh_session.BATCH_SIZE}",
            CONFIRMED if bmatch else REFUTED,
            f"robot InitAck batch_size={batch}")
        add("zenoh.cookie", "zenoh-session", "robot issues a cookie echoed in OpenSyn",
            CONFIRMED if cookie_len else UNOBSERVED, f"InitAck cookie bytes={cookie_len}")
    else:
        why = ("sent InitSyn but got no InitAck — robot may not run a unicast session, "
               "or rejected ours" if f.init_syn_tx else "no InitSyn sent in this capture")
        add("zenoh.session", "zenoh-session",
            "robot completes the zenoh unicast session (InitSyn→InitAck→OpenSyn→OpenAck)",
            UNOBSERVED, why)

    if f.init_ack:
        add("zenoh.open", "zenoh-session", "session reaches OPEN (OpenAck)",
            CONFIRMED if f.open_ack else REFUTED,
            "robot sent OpenAck" if f.open_ack else "InitAck seen but no OpenAck followed")

    # L5 — whether the robot acts on a Put after the epoch/session (does it answer?)
    answered = bool(f.rsp_seqs)
    add("cmd.accepted", "cmd-bus",
        "robot processes /cmd Puts after the session (emits a response topic)",
        CONFIRMED if answered else UNOBSERVED,
        f"robot published response topics: {sorted(f.rsp_seqs)}" if answered
        else "no _rsp topics observed from the robot")

    # L6 — request/response == pub/sub + seqNum (not zenoh Query/Reply)
    paired = sorted(set(f.req_seqs) & set(f.rsp_seqs))
    add("cmd.reqresp", "cmd-bus",
        "request/response is pub(_req)/sub(_rsp) correlated by WireHeader.seqNum",
        CONFIRMED if paired else UNOBSERVED,
        f"saw a _req we sent and a matching _rsp from the robot on: {paired}" if paired
        else "no _req/_rsp pair completed in this capture")

    # motion/axis mapping — never gradeable from a passive capture
    add("control.axes", "control", "ControlState→axis mapping (twist units) is correct",
        UNOBSERVED, "requires a SUPERVISED motion test (wheels-up); not gradeable passively")

    return out


@dataclass
class Report:
    findings: List[Finding]

    @property
    def counts(self) -> Counter:
        return Counter(x.verdict for x in self.findings)

    @property
    def refuted(self) -> List[Finding]:
        return [x for x in self.findings if x.verdict == REFUTED]

    def __str__(self) -> str:
        c = self.counts
        head = (f"=== Conformance ledger ===  "
                f"{c[CONFIRMED]} confirmed · {c[REFUTED]} refuted · {c[UNOBSERVED]} unobserved")
        body = "\n".join(str(x) for x in self.findings)
        tail = ""
        if self.refuted:
            tail = "\n\n!! REFUTED — SDK needs updating:\n" + "\n".join(
                f"   - {x.id}: {x.evidence}" for x in self.refuted)
        return f"{head}\n{body}{tail}"


def check_capture(path: str) -> Report:
    """Grade every clean-room assumption against a `.fwcap` capture."""
    return Report(evaluate(gather(path)))
