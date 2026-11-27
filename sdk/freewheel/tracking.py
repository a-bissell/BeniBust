"""UWB tracker / follow telemetry view (clean-room; see native-analysis/uwb-tracker.md).

Follow is computed on the robot; the app/SDK select a target and read back derived
status. This module turns the robot→app telemetry Puts into a live `TrackingState`
(follow on/off, distance, speed, target boxes, tracker battery/RSSI, lost events).

STATIC/experimental: the message *schemas* are recovered (cmd_schemas.json), but
the real telemetry **key expressions** and whether these ride inside a larger OSD
snapshot are only knowable on hardware. The monitor therefore identifies messages
by key-expression hint and falls back to nothing it can't confidently decode; once
you learn the real keyexprs, pin them with `register_topic()`.

Wire it like `ZenohMonitor` — hand its `on_message` to `MondoClient`:

    tmon = TrackingMonitor()
    robot = MondoClient(host, on_message=tmon.on_message)
    ...
    print(tmon.format_summary())
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .transport import ZENOH_CHANNELS as _ZCH
from . import cmd_proto, md_ts, zenoh, zenoh_pico

# Recovered telemetry message names (standalone *Data messages, not /cmd envelopes).
MSG_STATUS = "TrackingStatusData"          # status, trackingId, targetType, horizontalDis, horizontalSpeed, uwbFollowEnabled
MSG_TARGETS = "TrackingTargetDataData"     # targetCount (+ targets[] — repeated msg, decoded best-effort)
MSG_UWB_RC = "UwbRcStatusData"             # battery, rssi
MSG_LOST = "GatewayTrackingLostData"       # eventId[], subReason, triggeredAtMs

# distance/speed are integers on the wire; the app renders metres — assume mm.
# UNCONFIRMED scale: verify on hardware.
_DIST_PER_M = 1000.0


def guess_message(keyexpr: str) -> Optional[str]:
    """Best-effort map a telemetry key expression to a tracking message name.
    Real keyexprs are unknown pre-hardware; override with `register_topic()`."""
    k = keyexpr.lower()
    if "track" in k and "lost" in k:
        return MSG_LOST
    if "track" in k and ("target" in k or "box" in k):
        return MSG_TARGETS
    if "track" in k and ("status" in k or "state" in k or "follow" in k):
        return MSG_STATUS
    if "uwb" in k or "/rc" in k or "remote" in k:
        return MSG_UWB_RC
    return None


@dataclass
class TrackingState:
    follow_enabled: Optional[bool] = None
    status: Optional[int] = None
    tracking_id: Optional[int] = None
    target_type: Optional[int] = None
    distance_raw: Optional[int] = None         # horizontalDis (assume mm)
    speed_raw: Optional[int] = None            # horizontalSpeed (assume mm/s)
    target_count: Optional[int] = None
    targets: list = field(default_factory=list)   # [{id,x,y,w,h,state}]
    tracker_battery: Optional[int] = None      # %
    tracker_rssi: Optional[int] = None         # dBm
    lost: Optional[dict] = None                # {eventId, subReason, at_ms}
    updated: dict = field(default_factory=dict)   # field -> monotonic ts

    @property
    def distance_m(self) -> Optional[float]:
        return None if self.distance_raw is None else self.distance_raw / _DIST_PER_M

    @property
    def speed_ms(self) -> Optional[float]:
        return None if self.speed_raw is None else self.speed_raw / _DIST_PER_M

    def as_dict(self) -> dict:
        return {
            "follow_enabled": self.follow_enabled, "status": self.status,
            "tracking_id": self.tracking_id, "target_type": self.target_type,
            "distance_m": self.distance_m, "speed_ms": self.speed_ms,
            "target_count": self.target_count, "targets": self.targets,
            "tracker_battery": self.tracker_battery, "tracker_rssi": self.tracker_rssi,
            "lost": self.lost,
        }


class TrackingMonitor:
    """Accumulates tracker/follow telemetry from the robot→app zenoh Push stream."""

    def __init__(self, log=None):
        self.state = TrackingState()
        self.topic_map: dict = {}              # keyexpr -> msg name (learned/pinned)
        self.msgs = 0
        self.undecoded = 0
        self._log = log or (lambda m: None)
        self._link = zenoh.ZenohLink(on_data=self._on_data, log=log)
        self._pico = zenoh_pico.ZenohPicoDecoder()
        self.unseal = None                     # optional (keyexpr, payload) -> plaintext|None (MD-TS)

    def register_topic(self, keyexpr: str, msg_name: str) -> None:
        """Pin a learned keyexpr→message mapping (overrides the heuristic)."""
        self.topic_map[keyexpr] = msg_name

    # wire into MondoClient like ZenohMonitor
    def on_message(self, channel: int, payload: bytes) -> None:
        if channel not in _ZCH or not payload or payload[0] not in zenoh.ALL_TAGS:
            return
        self._link.feed(payload)

    def _on_data(self, frame) -> None:
        for m in self._pico.decode_batch(frame.payload):
            if isinstance(m, zenoh_pico.Put):
                payload = m.payload
                if self.unseal is not None:          # MD-TS: e.g. MondoClient.unseal
                    payload = self.unseal(m.keyexpr, payload)
                    if payload is None:
                        continue
                elif md_ts.decode_envelope(payload) is not None:
                    continue                         # sealed and no key: never misdecode it
                self.feed_put(m.keyexpr, payload)

    def feed_put(self, keyexpr: str, payload: bytes) -> bool:
        msg = (self.topic_map.get(keyexpr) or self.topic_map.get(cmd_proto.canonical_topic(keyexpr))
               or guess_message(keyexpr))
        if msg is None:
            return False
        return self.feed_message(msg, payload, keyexpr=keyexpr)

    def feed_message(self, msg_name: str, payload: bytes, keyexpr: str = "") -> bool:
        """Decode a known tracking message (raw `*Data` or `{header, data}` envelope) and fold it into state."""
        fields = None
        env_name = msg_name[:-4] if msg_name.endswith("Data") and msg_name[:-4] in cmd_proto.MESSAGES else None
        if env_name is not None:
            try:
                env = cmd_proto.decode_message(env_name, payload)
                if (isinstance(env.get("header"), dict) and isinstance(env.get("data"), dict)
                        and set(env.keys()) <= {"header", "data"}):
                    fields = env["data"]
            except Exception:                               # noqa: BLE001
                fields = None
        if fields is None:
            try:
                fields = cmd_proto.decode_message(msg_name, payload)
            except Exception:                               # noqa: BLE001
                self.undecoded += 1
                return False
        self._apply(msg_name, fields)
        self.msgs += 1
        if keyexpr:
            self.topic_map.setdefault(keyexpr, msg_name)
        return True

    def _apply(self, msg: str, f: dict) -> None:
        now = time.monotonic()
        st = self.state

        def mark(*names):
            for n in names:
                st.updated[n] = now

        if msg == MSG_STATUS:
            if "uwbFollowEnabled" in f:
                st.follow_enabled = bool(f["uwbFollowEnabled"])
            st.status = f.get("status", st.status)
            st.tracking_id = f.get("trackingId", st.tracking_id)
            st.target_type = f.get("targetType", st.target_type)
            st.distance_raw = f.get("horizontalDis", st.distance_raw)
            st.speed_raw = f.get("horizontalSpeed", st.speed_raw)
            mark("follow_enabled", "status", "distance_raw", "speed_raw")
        elif msg == MSG_UWB_RC:
            st.tracker_battery = f.get("battery", st.tracker_battery)
            st.tracker_rssi = f.get("rssi", st.tracker_rssi)
            mark("tracker_battery", "tracker_rssi")
        elif msg == MSG_TARGETS:
            st.target_count = f.get("targetCount", st.target_count)
            if isinstance(f.get("targets"), list):          # best-effort if decoded
                st.targets = f["targets"]
            mark("target_count", "targets")
        elif msg == MSG_LOST:
            st.lost = {"eventId": f.get("eventId"), "subReason": f.get("subReason"),
                       "at_ms": f.get("triggeredAtMs")}
            mark("lost")

    def snapshot(self) -> dict:
        return {**self.state.as_dict(), "msgs": self.msgs, "undecoded": self.undecoded,
                "topics": dict(self.topic_map)}

    def format_summary(self) -> str:
        s = self.state
        if not self.msgs:
            return "=== Tracker/Follow === (no tracking telemetry decoded yet)"
        follow = "ON" if s.follow_enabled else ("off" if s.follow_enabled is not None else "?")
        dist = f"{s.distance_m:.2f} m" if s.distance_m is not None else "?"
        spd = f"{s.speed_ms:.2f} m/s" if s.speed_ms is not None else "?"
        bat = f"{s.tracker_battery}%" if s.tracker_battery is not None else "?"
        rssi = f"{s.tracker_rssi} dBm" if s.tracker_rssi is not None else "?"
        lines = [
            "=== Tracker/Follow ===",
            f"  follow: {follow}   target#{s.tracking_id}  type={s.target_type}  "
            f"dist={dist}  speed={spd}",
            f"  tracker: battery {bat}  rssi {rssi}   targets={s.target_count}",
        ]
        if s.targets:
            for t in s.targets[:4]:
                lines.append(f"    target {t}")
        if s.lost:
            lines.append(f"  !! tracking lost: {s.lost}")
        return "\n".join(lines)
