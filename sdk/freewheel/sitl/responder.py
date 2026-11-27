"""A virtual robot for the offline tests (UCP + zenoh + `md_upgrade`, on loopback).

Extracted from the research repository's simulator, keeping only the responder the
offline suites drive. It has no dependency on the web console, its HTTP server, or
its browser assets, so it ships with the jailbreak rather than with the console.

Everything here runs on loopback with no hardware: the UCP transport handshake and
heartbeats, zenoh-over-UCP frames, `/cmd` request/response, synthetic telemetry, the
MD-TS encrypted session, BLE-facilitated Wi-Fi provisioning state, and the
`md_upgrade` v1 inbox + v2 task API the OTA uploader talks to.
"""
from __future__ import annotations

import json
import math
import os
import socket
import struct
import threading
import time
from typing import Dict, List, Optional

from .. import cmd_proto, md_ts
from ..control import fields_to_twist, unpack_control
from ..transport import (
    ACK,
    CH_CONTROL,
    CH_VIDEO,
    CH_ZENOH,
    HEADER,
    LEAVE,
    MAGIC,
    MAX_PAYLOAD,
    SYNC,
    decode_segments,
    encode_segment,
    seq_diff,
)
from ..zenoh import ALL_TAGS as _ZTAGS, ZenohMonitor, encode_data, encode_ready, iter_frames
from ..zenoh_pico import Put, ZenohPicoDecoder, encode_batch, encode_frame, encode_put
from ..zenoh_session import MID_INIT, MID_OPEN, encode_init_ack, encode_open_ack
from ._video import generate_sim_h265_clip

_TEXT = 17

def synthetic_telemetry(n: int, extra=(), seal=None) -> bytes:
    """Genuine zenoh-pico FRAME→PUSH→PUT batch of synthetic telemetry."""
    battery = max(15, 100 - (n // 80) % 85)
    vx = round(math.sin(n / 20.0), 3)
    puts = [
        ("state/battery", bytes([battery & 0xFF])),
        ("state/pose", struct.pack("<fff", vx, 0.0, 0.11)),
        ("state/mode", (b"idle" if (n // 30) % 2 else b"run"), _TEXT),
        ("imu/accel", struct.pack("<fff", 0.0, 0.0, 9.81)),
        ("motor/temp", bytes([40 + (n % 7)])),
        *extra,
    ]
    puts = [(cmd_proto.DEVICE_PREFIX + p[0],) + tuple(p[1:]) for p in puts]
    if seal is not None:
        puts = [(p[0], seal(p[0], p[1])) + tuple(p[2:]) for p in puts]
    return encode_batch(puts)

class SimResponder:
    STATUS_HZ = 10.0

    def __init__(self, host: str = "127.0.0.1", port: int = 9007,
                 md_ts_responder: Optional["md_ts.Responder"] = None,
                 enable_video: bool = True):
        self.addr = (host, port)
        self._sec = md_ts_responder
        self._enable_video = enable_video
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._lock = threading.Lock()
        self._decoded: Optional[dict] = None
        self._raw_ctrl: Optional[dict] = None
        self._n = 0
        self._peer = None
        self._rx_zenoh = ZenohMonitor()
        self._cli_epoch = None
        self._session_open = False
        self._sim_zid = os.urandom(16)
        self._cookie = os.urandom(8)
        self._resp_pico = ZenohPicoDecoder()
        self._sim_sn = 0
        self._ucp_lock = threading.Lock()
        self._ucp_snd = 0
        self._ucp_rcv = 0
        self._ucp_unrel = 0
        self._video_sn = 0

        # Synthetic robot domain state
        self._following = False
        self._follow_target = 0
        self._follow_dist_mm = 3000
        self._target_type = 0
        self._mission_id = 1
        self._sub_mode = 0
        self._recording = False
        self._rec_started_at = 0.0
        self._zoom_data = 10
        self._eis_level = 1
        self._profile_id = 46
        self._hms_faults: Dict[tuple, dict] = {}
        self._hms_cmd_seq = 100
        self._wifi_mode = "ap"
        self._wifi_ssid = "Beni-SIM001"
        self._prov_staged: Optional[dict] = None
        self._prov_state = 0
        self._prov_fail = 0
        self._ota_task: Optional[dict] = None
        self._ota_grant_token = ""
        self._ota_uploaded = 0
        self._ota_expected = 0

    SIM_SERIAL = "YDSBSIM00000001"

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(self.addr)
        s.settimeout(0.5)
        self._sock = s
        self._running = True
        threading.Thread(target=self._loop, name="fw-sim", daemon=True).start()
        threading.Thread(target=self._status_loop, name="fw-sim-tx", daemon=True).start()
        if self._enable_video:
            threading.Thread(target=self._video_loop, name="fw-sim-vid", daemon=True).start()

    SIM_EPOCH = 0x0042

    def _send_zenoh(self, s, peer, payload: bytes) -> None:
        with self._ucp_lock:
            sn = self._ucp_snd
            self._ucp_snd = (self._ucp_snd + 1) & 0xFFFF
            seg = encode_segment(CH_ZENOH, payload, reliable=True, more=False,
                                 una=self._ucp_rcv, sn=sn)
        try:
            s.sendto(seg, peer)
        except OSError:
            pass

    def _send_video_au(self, s, peer, au: bytes) -> None:
        for off in range(0, len(au), MAX_PAYLOAD):
            chunk = au[off:off + MAX_PAYLOAD]
            more = (off + MAX_PAYLOAD) < len(au)
            with self._ucp_lock:
                sn = self._video_sn
                self._video_sn = (self._video_sn + 1) & 0xFFFF
                seg = encode_segment(CH_VIDEO, chunk, reliable=False, more=more,
                                     una=self._ucp_rcv, sn=sn)
            try:
                s.sendto(seg, peer)
            except OSError:
                return

    def _send_ack(self, s, peer) -> None:
        with self._ucp_lock:
            sn = self._ucp_unrel
            self._ucp_unrel = (self._ucp_unrel + 1) & 0xFFFF
            seg = encode_segment(CH_CONTROL, b"", reliable=False, more=False,
                                 una=self._ucp_rcv, sn=sn, sack=(self._ucp_rcv, 0, 0))
        try:
            s.sendto(seg, peer)
        except OSError:
            pass

    def _video_loop(self) -> None:
        clip = generate_sim_h265_clip()
        if not clip:
            return
        idx = 0
        while self._running:
            time.sleep(0.125)
            s, peer = self._sock, self._peer
            if s is None or peer is None:
                continue
            with self._lock:
                rc = self._raw_ctrl
            if rc is not None and rc.get("no_liveview"):
                continue
            self._send_video_au(s, peer, clip[idx % len(clip)])
            idx += 1

    def _status_loop(self) -> None:
        n = 0
        while self._running:
            time.sleep(1.0 / self.STATUS_HZ)
            s, peer = self._sock, self._peer
            if s is None or peer is None or not self._session_open or self._cli_epoch is None:
                continue
            n += 1
            if self._sec is not None and self._sec.session is None:
                continue
            extra = list(self._tracking_puts(n)) + list(self._robot_status_puts(n))
            self._send_zenoh(s, peer, encode_data(self._cli_epoch & 0xFFFF,
                                                 synthetic_telemetry(n, extra, seal=self._seal)))

    def _seal(self, key: str, payload: bytes) -> bytes:
        sess = self._sec.session if self._sec is not None else None
        return sess.seal(key, payload) if sess is not None else payload

    def _robot_status_puts(self, n: int):
        with self._lock:
            dec = dict(self._decoded) if self._decoded else None
            rc = dict(self._raw_ctrl) if self._raw_ctrl else None
        battery = max(15, 100 - (n // 80) % 85)
        islock = bool(rc["islock"]) if rc else True
        ispause = bool(rc["ispause"]) if rc else False
        vx_cms = int(round((dec["vx"] if dec else 0.0) * 100))
        h_tenth_cm = int(round((dec["height_m"] if dec else 0.11) * 1000))
        rec_dur = int(time.monotonic() - self._rec_started_at) if self._recording else 0
        try:
            pmu = cmd_proto.build_cmd("status/pmu/osd_status", seq=n, soc=battery, powerBits=0)
            rob = cmd_proto.build_cmd(
                "status/robot/status",
                seq=n,
                robotState=(0 if islock else 3),
                velocity=vx_cms,
                height=h_tenth_cm,
                obstacleDis=180,
                pitchAngle=int(round((dec["pitch"] if dec else 0.0) * 573.0)),
                gimbalAngle=int(round((dec["gimbal_yaw"] if dec else 0.0) * 114.6)),
                rollAngle=int(round((dec["roll"] if dec else 0.0) * 573.0)),
                sportMode=(rc["max_speed"] if rc else 0),
            )
            sched = cmd_proto.build_cmd(
                "status/scheduler/status",
                seq=n,
                currentMode=self._mission_id,
                subMode=self._sub_mode,
                isLocked=(1 if islock else 0),
                isPaused=(1 if ispause else 0),
                egoActive=(1 if (self._mission_id == 1 and self._sub_mode == 6) else 0),
                obstacleAvoidanceFlags=(rc["nav_flag"] if rc else 0),
            )
            cam = cmd_proto.build_cmd(
                "status/camera/status",
                seq=n,
                recState=(1 if self._recording else 0),
                recDurationS=rec_dur,
                zoomData=self._zoom_data,
                eisStatus=self._eis_level,
                currentProfileId=self._profile_id,
                vtFrameRate=8,
                vtBitrate=420,
            )
            return [
                ("status/pmu/osd_status", pmu),
                ("status/robot/status", rob),
                ("status/scheduler/status", sched),
                ("status/camera/status", cam),
            ]
        except Exception:  # noqa: BLE001
            return ()

    def _tracking_puts(self, n: int):
        if self._following and self._follow_dist_mm > 800:
            self._follow_dist_mm -= 40
        battery = max(0, 100 - n // 120)
        cx = 0.5 + 0.18 * math.sin(n / 12.0)
        try:
            status = cmd_proto.encode_message("TrackingStatusData", {
                "status": 1 if self._following else 0,
                "trackingId": self._follow_target,
                "targetType": self._target_type,
                "horizontalDis": self._follow_dist_mm,
                "horizontalSpeed": 600 if self._following else 0,
                "uwbFollowEnabled": 1 if self._following else 0,
            })
            uwb = cmd_proto.encode_message("UwbRcStatusData",
                                           {"battery": battery, "rssi": -55 - (n % 7)})
            targets = [
                {
                    "id": 101, "centerPosX": round(cx, 3), "centerPosY": 0.48,
                    "width": 0.20, "height": 0.46,
                    "targetState": (1 if self._following and self._follow_target == 101 else 0),
                    "reservedStateFlags": 0,
                },
                {
                    "id": 202, "centerPosX": round(1.0 - cx * 0.6, 3), "centerPosY": 0.66,
                    "width": 0.16, "height": 0.24,
                    "targetState": (1 if self._following and self._follow_target == 202 else 0),
                    "reservedStateFlags": 1,
                },
            ]
            tgt = cmd_proto.encode_message("TrackingTargetDataData", {
                "targetCount": len(targets),
                "targets": targets,
            })
            return [
                ("status/tracking/status", status),
                ("status/rc/uwb", uwb),
                ("data/tracking/target_data", tgt),
            ]
        except Exception:  # noqa: BLE001
            return ()

    def inject_hms_fault(self, code: int, instance: int = 0, confirm: bool = True) -> None:
        s, peer = self._sock, self._peer
        if s is None or peer is None or not self._session_open or self._cli_epoch is None:
            return
        full = int(code) & 0xFFFFFFFF
        self._hms_faults[(full, int(instance))] = {"code": full, "instance": int(instance)}
        ev = cmd_proto.build_cmd(
            "status/hms/event_broadcast",
            seq=1,
            faultCode=full,
            instanceId=int(instance),
            moduleId=(full >> 16) & 0xFF,
            kind=1,
            severity=2,
            timestampMs=int(time.time() * 1000),
        )
        key = cmd_proto.DEVICE_PREFIX + "status/hms/event_broadcast"
        self._sim_sn += 1
        self._send_zenoh(s, peer, encode_data(self._cli_epoch & 0xFFFF, encode_frame(
            self._sim_sn, encode_put(key, self._seal(key, ev), 13))))
        if confirm:
            self._hms_cmd_seq += 1
            req = cmd_proto.build_cmd(
                "cmd/hms/action_request",
                commandId=self._hms_cmd_seq,
                sourceFaultCode=full,
                actionId=1,
                instanceId=int(instance),
                operation=1,
                dispatcherInstanceId=7,
                deliveryStoreId=b"simstore",
            )
            akey = cmd_proto.DEVICE_PREFIX + "cmd/hms/action_request"
            self._sim_sn += 1
            self._send_zenoh(s, peer, encode_data(self._cli_epoch & 0xFFFF, encode_frame(
                self._sim_sn, encode_put(akey, self._seal(akey, req), 13))))

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()
            self._sock = None

    def decoded(self):
        with self._lock:
            return (dict(self._decoded), self._n) if self._decoded else (None, 0)

    def published(self):
        return self._rx_zenoh.snapshot()["topics"]

    def _loop(self) -> None:
        assert self._sock is not None
        while self._running:
            try:
                data, peer = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            self._peer = peer
            if data[:8] == SYNC:
                # A new ucp:sync opens a fresh session: the client restarts its
                # sequence numbers at 0, so the receive counter must reset too
                # (otherwise every frame of the second session looks stale).
                with self._ucp_lock:
                    self._ucp_rcv = 0
                    self._ucp_snd = 0
                    self._ucp_unrel = 0
                self._cli_epoch = None
                self._session_open = False
                self._resp_pico = ZenohPicoDecoder()
                self._sock.sendto(ACK, peer)
                continue
            if data[:8] == LEAVE or len(data) < HEADER.size or data[0] != MAGIC:
                continue
            for seg in decode_segments(data):
                payload = seg["payload"]
                if seg["reliable"]:
                    with self._ucp_lock:
                        d = seq_diff(seg["sn"], self._ucp_rcv)
                        if d == 0:
                            self._ucp_rcv = (self._ucp_rcv + 1) & 0xFFFF
                    self._send_ack(self._sock, peer)
                    if d != 0:
                        continue
                    if payload and payload[0] in _ZTAGS:
                        self._on_zenoh(bytes(payload), peer)
                    continue
                if seg["sack"] is None and payload and payload[0] in _ZTAGS:
                    self._on_zenoh(bytes(payload), peer)
                    continue
                if len(payload) != 8:
                    continue
                raw = unpack_control(bytes(payload))
                with self._lock:
                    self._raw_ctrl = raw
                    self._decoded = fields_to_twist(raw)
                    self._n += 1

    def _on_zenoh(self, payload: bytes, peer) -> None:
        s = self._sock
        if s is None:
            return
        tag = payload[0]
        if tag == 0xA4:
            self._cli_epoch = int.from_bytes(payload[1:5], "big")
            self._session_open = False
            self._send_zenoh(s, peer, encode_ready(self._cli_epoch))
            return
        if tag == 0xA6:
            self._session_open = False
            return
        for fr in iter_frames(payload):
            if not fr.is_data or not fr.payload:
                continue
            batch = fr.payload
            mid, is_ack = batch[0] & 0x1F, bool(batch[0] & 0x20)
            if mid == MID_INIT and not is_ack:
                ack = encode_init_ack(self._sim_zid, cookie=self._cookie)
                self._send_zenoh(s, peer, encode_data(self._cli_epoch & 0xFFFF, ack))
                return
            if mid == MID_OPEN and not is_ack:
                self._send_zenoh(s, peer, encode_data(self._cli_epoch & 0xFFFF,
                                                    encode_open_ack(initial_sn=0)))
                self._session_open = True
                return
        self._rx_zenoh.on_message(0, payload)
        self._maybe_respond(payload, peer)

    def _maybe_respond(self, payload: bytes, peer) -> None:
        s = self._sock
        if s is None:
            return
        for fr in iter_frames(payload):
            if not fr.is_data:
                continue
            for m in self._resp_pico.decode_batch(fr.payload):
                if not isinstance(m, Put):
                    continue
                topic = cmd_proto.canonical_topic(m.keyexpr)
                body = m.payload
                if topic == md_ts.SECURITY_TOPIC:
                    reply = self._sec.handle(body) if self._sec is not None else None
                    if reply is not None:
                        self._sim_sn += 1
                        self._send_zenoh(s, peer, encode_data(self._cli_epoch & 0xFFFF, encode_frame(
                            self._sim_sn, encode_put(md_ts.DEVICE_SECURITY_KEYEXPR, reply, 13))))
                    continue
                if self._sec is not None:
                    sess = self._sec.session
                    if sess is None or md_ts.decode_envelope(body) is None:
                        continue
                    body = md_ts.open_envelope(sess, m.keyexpr, body)
                    if body is None:
                        continue
                self._apply_sim_cmd(topic, body)
                rsp = cmd_proto.response_topic(topic)
                if rsp is None:
                    continue
                try:
                    dec = cmd_proto.decode_cmd(topic, body)
                    seq = dec["seqNum"]
                    rsp_fields = self._build_rsp_fields(topic, dec["data"])
                    rsp_payload = cmd_proto.build_cmd(rsp, seq=seq, **rsp_fields)
                except Exception:  # noqa: BLE001
                    continue
                key = cmd_proto.DEVICE_PREFIX + rsp
                self._sim_sn += 1
                self._send_zenoh(s, peer, encode_data(self._cli_epoch & 0xFFFF, encode_frame(
                    self._sim_sn, encode_put(key, self._seal(key, rsp_payload), 13))))

    def _apply_sim_cmd(self, topic: str, body: bytes) -> None:
        try:
            data = cmd_proto.decode_cmd(topic, body)["data"]
        except Exception:  # noqa: BLE001
            return
        if topic == "cmd/tracking/ctrl_cmd":
            self._following = bool(data.get("startTracking"))
            self._follow_target = int(data.get("selectedId") or (101 if self._following else 0))
            if self._following:
                self._follow_dist_mm = 3000
        elif topic == "cmd/tracking/model_switch_cmd":
            self._target_type = int(data.get("targetType", 0))
        elif topic == "cmd/mission/request":
            self._mission_id = int(data.get("missionId", self._mission_id))
            self._sub_mode = int(data.get("subMode", 0))
        elif topic == "cmd/camera/record_req":
            act = int(data.get("action", 1))
            self._recording = (act == 1)
            if self._recording:
                self._rec_started_at = time.monotonic()
        elif topic == "cmd/camera/config_switch_cmd":
            self._profile_id = int(data.get("profileId", self._profile_id))
        elif topic == "cmd/camera/unified_cmd":
            ct = int(data.get("cmdType", 0))
            if ct & 0x0004 and data.get("zoomData"):
                self._zoom_data = int(data["zoomData"])
            if ct & 0x0008:
                self._eis_level = int(data.get("eisLevel", 0))
            if ct & 0x0010 and data.get("recordProfileId"):
                self._profile_id = int(data["recordProfileId"])
        elif topic == "cmd/nm/wifi_switch_to_ap_req":
            self._wifi_mode = "ap"
            self._wifi_ssid = "Beni-SIM001"
        elif topic == "cmd/hms/action_response":
            # Clear the oldest pending fault on acknowledge in sim
            if self._hms_faults:
                k = next(iter(self._hms_faults))
                f = self._hms_faults.pop(k)
                s, peer = self._sock, self._peer
                if s is not None and peer is not None and self._cli_epoch is not None:
                    ev = cmd_proto.build_cmd(
                        "status/hms/event_broadcast",
                        seq=1,
                        faultCode=f["code"],
                        instanceId=f["instance"],
                        moduleId=(f["code"] >> 16) & 0xFF,
                        kind=2,
                        severity=1,
                        timestampMs=int(time.time() * 1000),
                    )
                    key = cmd_proto.DEVICE_PREFIX + "status/hms/event_broadcast"
                    self._sim_sn += 1
                    self._send_zenoh(s, peer, encode_data(self._cli_epoch & 0xFFFF, encode_frame(
                        self._sim_sn, encode_put(key, self._seal(key, ev), 13))))

    def _build_rsp_fields(self, req_topic: str, req_data: dict) -> dict:
        if req_topic == "cmd/common/get_version_req":
            return {
                "retCode": 0,
                "majorVersion": 26,
                "minorVersion": 11,
                "hardwareVersion": b"LZ110-SIM",
                "loaderVersion": b"BL-1.0",
                "firmwareVersion": b"V26.11.00.sim",
                "isMassProduct": 0,
            }
        if req_topic == "cmd/common/get_crypto_info_req":
            return {
                "retCode": 0,
                "cmdVersion": 2,
                "isEncrypted": 1 if self._sec is not None else 0,
                "batchId": b"SIM-BATCH-001",
            }
        if req_topic == "cmd/common/ping_req":
            return {"retCode": 0, "pingData": req_data.get("pingData", b"pong")}
        if req_topic == "cmd/robot/sn_req":
            sn = self.SIM_SERIAL.encode("utf-8")
            return {"snType": int(req_data.get("snType", 0) or 0), "lens": len(sn), "sn": sn}
        if req_topic == "cmd/ota/upgrade_control_req":
            cmd = int(req_data.get("controlCmd", 3) or 0)
            ctx = req_data.get("task") or {}
            if cmd == 0:                     # START: mint a V2 task + Upload-Token
                uid = str(ctx.get("upgradeId") or "")
                token = self._ota_grant_token = f"sim-grant-{uid[:8]}"
                self._ota_task = {
                    "protocolVersion": 2,
                    "upgradeId": uid,
                    "deviceId": str(ctx.get("deviceId") or self.SIM_SERIAL),
                    "state": "CREATED",
                    "uploadGrantToken": token,
                    "offset": 0,
                    "revision": 1,
                }
                self._ota_uploaded = 0
                self._ota_expected = int(ctx.get("size", 0) or 0)
                return {"retCode": 0, "currentUpgradeStage": 0, "task": dict(self._ota_task)}
            if cmd == 4:                     # INSTALL
                if self._ota_task:
                    self._ota_task["state"] = "INSTALLING"
                return {"retCode": 0, "currentUpgradeStage": 5,
                        "task": dict(self._ota_task or {"state": "INSTALLING"}, errorCode="")}
            if cmd == 1:                     # CANCEL
                if self._ota_task:
                    self._ota_task["state"] = "CANCELLED"
                return {"retCode": 0, "currentUpgradeStage": 0, "task": dict(self._ota_task or {})}
            return {"retCode": 0, "currentUpgradeStage": 3, "task": dict(self._ota_task or {})}
        if req_topic == "cmd/mission/request":
            return {
                "resultCode": 0,
                "currentMissionId": self._mission_id,
                "currentSubMode": self._sub_mode,
            }
        if req_topic == "cmd/camera/record_req":
            return {
                "action": int(req_data.get("action", 1)),
                "requestId": int(req_data.get("requestId", 0)),
                "retCode": 0,
                "state": 1 if self._recording else 0,
            }
        if req_topic == "status/hms/query_active":
            faults = list(self._hms_faults.values())
            return {
                "count": len(faults),
                "faultCodes": [f["code"] for f in faults],
                "instanceIds": [f["instance"] for f in faults],
                "moduleIds": [(f["code"] >> 16) & 0xFF for f in faults],
                "retCode": 0,
                "requestId": int(req_data.get("requestId", 0)),
            }
        if req_topic == "cmd/nm/wifi_scan_req":
            return {
                "result": 0,
                "apCount": 2,
                "totalFound": 2,
                "resv": b"\x00" * 4,
                "aps": [
                    {
                        "ssidLen": 10, "ssid": b"HomeNet-5G",
                        "bssid": bytes([0xAA, 0x11, 0x22, 0x33, 0x44, 0x01]),
                        "channel": 36, "rssi": -49, "security": 2, "resv": b"\x00" * 4,
                    },
                    {
                        "ssidLen": 11, "ssid": b"GuestOpen24",
                        "bssid": bytes([0xAA, 0x11, 0x22, 0x33, 0x44, 0x02]),
                        "channel": 6, "rssi": -68, "security": 0, "resv": b"\x00" * 4,
                    },
                ],
                "recentSsidLen": len(self._wifi_ssid),
                "recentSsid": self._wifi_ssid.encode("utf-8"),
                "recentPskLen": 0,
                "recentPsk": b"",
            }
        if req_topic == "cmd/nm/wifi_connect_req":
            raw_ssid = bytes(req_data.get("ssid") or b"")
            n = int(req_data.get("ssidLen") or len(raw_ssid))
            ssid = raw_ssid[:n].decode("utf-8", errors="replace")
            raw_psk = bytes(req_data.get("psk") or b"")
            pn = int(req_data.get("pskLen") or len(raw_psk))
            psk = raw_psk[:pn]
            self._prov_staged = {
                "ssid": ssid,
                "psk": psk,
                "uuid": bytes(req_data.get("uuid") or b"\x00" * 16),
            }
            self._prov_state = 0
            self._prov_fail = 0
            return {"result": 0, "ssidLen": len(ssid), "ssid": ssid.encode("utf-8"), "resv": b"\x00" * 4}
        if req_topic == "cmd/nm/wifi_provision_start_req":
            u = bytes(req_data.get("uuid") or b"\x00" * 16)
            return {"result": 0, "timeoutSec": 25, "resv": b"\x00" * 2, "totalTimeoutSec": 45, "uuid": u}
        if req_topic == "cmd/nm/wifi_provision_commit_req":
            u = bytes(req_data.get("uuid") or b"\x00" * 16)
            staged = self._prov_staged or {"ssid": "HomeNet-5G", "psk": b"", "uuid": u}
            if staged.get("psk") == b"wrong-pass":
                self._prov_state = 3
                self._prov_fail = 1   # WRONG_KEY
            else:
                self._prov_state = 2
                self._prov_fail = 0
                self._wifi_mode = "sta"
                self._wifi_ssid = staged["ssid"]
            return {"result": 0, "timeoutSec": 25, "resv": b"\x00" * 2, "totalTimeoutSec": 45, "uuid": u}
        if req_topic == "cmd/nm/wifi_provision_result_req":
            u = bytes(req_data.get("uuid") or b"\x00" * 16)
            sb = self._wifi_ssid.encode("utf-8")
            ip = bytes([192, 168, 1, 42]) if self._prov_state == 2 else b"\x00\x00\x00\x00"
            return {
                "result": 0,
                "uuidMatch": 1,
                "state": self._prov_state,
                "failReason": self._prov_fail,
                "uuid": u,
                "ssidLen": len(sb),
                "ssid": sb,
                "ipv4": ip,
                "channel": 36 if self._prov_state == 2 else 0,
                "rssi": -51 if self._prov_state == 2 else 0,
                "resv": b"\x00" * 4,
            }
        if req_topic == "cmd/nm/wifi_switch_to_station_req":
            self._wifi_mode = "sta"
            return {"result": 0, "currentMode": 2, "resv": b"\x00" * 4}
        return {}

