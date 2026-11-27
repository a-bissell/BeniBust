"""High-level Mondo client: connect, seed, and a 50 Hz control loop.

Mirrors the app's ControlLoop: after the UCP handshake it sends a short burst of
seed frames carrying [0xFE], then streams the 8-byte control word as a channel-0
heartbeat every 20 ms. Mutate control via the setters; the tx thread always sends
the latest ControlState.

SAFE DEFAULTS: starts locked (islock=True) and max_speed=0, so nothing moves until
you call unlock() and raise max_speed. STATIC-ONLY: untested on hardware.
"""
from __future__ import annotations

import os
import queue
import threading
import time
from typing import Callable, Optional

from .control import ControlState, twist_to_axes
from .transport import CH_ZENOH, ZENOH_CHANNELS, UcpTransport

HEARTBEAT_INTERVAL_S = 0.020        # 50 Hz (UcpManager.HEARTBEAT_INTERVAL_MS = 20)
SEED_PAYLOAD = b"\xFE"              # kSeedingHeartbeatPayload
SEED_DURATION_S = 0.5              # ~500 ms seed window before control stream


class MondoClient:
    def __init__(self, host: str = "192.168.7.1", port: int = 9007,
                 on_message: Optional[Callable[[int, bytes], None]] = None,
                 on_raw: Optional[Callable[[bytes], None]] = None,
                 on_send: Optional[Callable[[bytes], None]] = None,
                 listen_only: bool = False, passive: bool = False,
                 log: Optional[Callable[[str], None]] = None,
                 security: str = "auto", identity=None, robot_public_key: Optional[bytes] = None):
        self._log = log or (lambda m: print(f"[mondo] {m}"))
        self._user_on_message = on_message
        self._t = UcpTransport(host, port, on_message=self._dispatch_rx, on_raw=on_raw,
                               on_send=on_send, log=self._log)
        self.state = ControlState()            # locked by default
        self._lock = threading.Lock()
        self._tx_thread: Optional[threading.Thread] = None
        self._running = False
        self._seeding = True
        # request/response: inbound Push routing to seqNum-keyed waiters
        self._resp_dec = None                  # lazy ZenohPicoDecoder
        self._waiters: dict = {}               # (keyexpr, seqNum) -> {event, result}
        self._declared_subs: set = set()
        self._req_seq = 1
        # listen_only: motion is impossible — state is pinned to locked+paused and the
        # motion setters are refused. passive: after seeding, transmit nothing at all
        # (fully silent; the robot may drop us on its own watchdog).
        self.listen_only = listen_only
        self.passive = passive
        self._pub = None                       # lazy ZenohPublisher (send side)
        # MD-TS (secure_v2): "auto" negotiates if the robot answers and an identity
        # exists, else plaintext; "md-ts" requires it; "plaintext" never tries.
        if security not in ("auto", "md-ts", "plaintext"):
            raise ValueError(f"security must be auto|md-ts|plaintext, not {security!r}")
        self.security = security
        self._identity = identity               # md_ts.Identity, a path, or None (load default)
        self._robot_pub = robot_public_key
        self._mdts = None                       # md_ts.Session once negotiated
        self._sec_state = "none"                # none | plaintext | md-ts
        self._sec_lock = threading.RLock()
        self._sec_q: "queue.Queue[bytes]" = queue.Queue()
        if listen_only:
            self.state.islock = True
            self.state.ispause = True

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> None:
        self._t.connect()
        self._running = True
        self._tx_thread = threading.Thread(target=self._tx_loop, name="mondo-tx", daemon=True)
        self._tx_thread.start()
        self._log("connected; seeding…")

    def close(self) -> None:
        # Best-effort: command a safe state briefly, then tear down.
        with self._lock:
            self.state.islock = True
            self.state.ispause = True
        time.sleep(0.05)
        if self._pub is not None:
            self._pub.close()                  # A6 CLOSE the publish epoch
        self._running = False
        if self._tx_thread is not None:
            self._tx_thread.join(timeout=1.0)
        self._t.close()
        self._log("closed")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- control API -------------------------------------------------------
    def _refuse_if_listen(self, what: str) -> bool:
        if self.listen_only:
            self._log(f"listen_only: refused {what} (no motion allowed in this mode)")
            return True
        return False

    def unlock(self) -> None:
        if self._refuse_if_listen("unlock()"):
            return
        with self._lock:
            self.state.islock = False

    def lock(self) -> None:
        with self._lock:
            self.state.islock = True

    def estop(self) -> None:
        with self._lock:
            self.state.ispause = True

    def clear_estop(self) -> None:
        if self._refuse_if_listen("clear_estop()"):
            return
        with self._lock:
            self.state.ispause = False

    def set_axes(self, ch0=None, ch1=None, ch2=None, ch3=None, roll=None) -> None:
        """Set any normalized axis in [-1.0, 1.0]; omitted axes are unchanged."""
        if self._refuse_if_listen("set_axes()"):
            return
        with self._lock:
            for name, val in (("ch0", ch0), ("ch1", ch1), ("ch2", ch2),
                              ("ch3", ch3), ("roll", roll)):
                if val is not None:
                    setattr(self.state, name, float(val))

    def set(self, **fields) -> None:
        """Set any ControlState field by name (height, max_speed, nav_flag, flip_cmd, …)."""
        if self._refuse_if_listen("set()"):
            return
        with self._lock:
            for k, v in fields.items():
                if not hasattr(self.state, k):
                    raise AttributeError(f"unknown control field: {k}")
                setattr(self.state, k, v)

    def twist(self, vx: float = None, wz: float = None, gimbal_yaw: float = None,
              pitch: float = None, roll: float = None, height_m: float = None) -> None:
        """Command in PHYSICAL units (from Mondo open-beni), converted to the
        normalized axes internally. Only provided args change.

            vx m/s (±2), wz rad/s (±5, yaw), gimbal_yaw rad (±5),
            pitch rad (±0.1), roll rad (±0.1), height_m metres (0.10..0.12)

        NOTE: the axis mapping is an UNCONFIRMED hypothesis cross-referenced with
        open-beni — verify on hardware / in the open-beni MuJoCo sim. You must
        unlock() and set a nonzero max_speed for motion.
        """
        if self._refuse_if_listen("twist()"):
            return
        fields = twist_to_axes(vx=vx, wz=wz, gimbal_yaw=gimbal_yaw,
                               pitch=pitch, roll=roll, height_m=height_m)
        height = fields.pop("height", None)
        with self._lock:
            for k, v in fields.items():
                setattr(self.state, k, v)
            if height is not None:
                self.state.height = height

    def snapshot(self) -> ControlState:
        with self._lock:
            return ControlState(**vars(self.state))

    # -- zenoh publish (send side) ----------------------------------------------
    def publisher(self):
        """The lazily-created ZenohPublisher bound to this link (reliable channel 3)."""
        if self._pub is None:
            from .zenoh import ZenohPublisher
            self._pub = ZenohPublisher(send=lambda p: self._t.send(CH_ZENOH, p, reliable=True),
                                       transport=self._t, log=self._log)
        return self._pub

    # -- MD-TS (secure_v2) ----------------------------------------------------
    @property
    def security_state(self) -> str:
        """"none" (not negotiated yet), "plaintext", or "md-ts"."""
        return self._sec_state

    def _load_identity(self):
        from . import md_ts
        ident = self._identity
        if isinstance(ident, str):
            ident = md_ts.Identity.load(ident)
        elif ident is None:
            ident = md_ts.Identity.load_default()
        self._identity = ident
        return ident

    def _subscribe(self, keyexpr: str) -> None:
        if keyexpr in self._declared_subs:
            return
        self.publisher().declare_subscriber(keyexpr, sub_id=len(self._declared_subs) + 1)
        self._declared_subs.add(keyexpr)
        time.sleep(0.05)

    def subscribe(self, keyexpr: str) -> None:
        """Declare a zenoh subscriber (e.g. `"device/**"` for telemetry) so the robot
        starts publishing to us; idempotent."""
        self._subscribe(keyexpr)

    def secure(self, mode: Optional[str] = None, timeout: float = 2.0) -> str:
        """Negotiate the MD-TS session if it hasn't been (idempotent). Returns the
        resulting `security_state`. Raises md_ts.MdTsError if the robot rejects us
        (e.g. UNAUTHORIZED_CLIENT: pair over BLE first) or if mode="md-ts" fails."""
        from . import md_ts
        from .zenoh_pico import ENC_APPLICATION_PROTOBUF
        mode = mode or self.security
        with self._sec_lock:
            if self._sec_state != "none":
                return self._sec_state
            if mode == "plaintext":
                self._sec_state = "plaintext"
                return self._sec_state
            ident = self._load_identity()
            if ident is None:
                if mode == "md-ts":
                    raise md_ts.MdTsError("NO_IDENTITY", "no MD-TS identity file found", md_ts.PAIRING_HINT)
                self._log("md-ts: no identity file; using plaintext (" + md_ts.PAIRING_HINT + ")")
                self._sec_state = "plaintext"
                return self._sec_state
            pub = self.publisher()
            pub.open()
            self._subscribe(md_ts.DEVICE_SECURITY_KEYEXPR)
            while not self._sec_q.empty():
                self._sec_q.get_nowait()

            def _recv(t):
                try:
                    return self._sec_q.get(timeout=t)
                except queue.Empty:
                    return None

            robot_pub = self._robot_pub or ident.lookup_robot_key(host=self._t.host)
            sess = md_ts.negotiate(
                ident, lambda env: pub.put(md_ts.APP_SECURITY_KEYEXPR, env, encoding=ENC_APPLICATION_PROTOBUF),
                _recv, robot_public_key=robot_pub, mode=mode, timeout=timeout)
            self._mdts = sess
            self._sec_state = "md-ts" if sess else "plaintext"
            self._log("md-ts: session established" if sess else
                      "md-ts: robot did not answer the handshake; using plaintext")
            return self._sec_state

    def unseal(self, keyexpr: str, payload: bytes) -> Optional[bytes]:
        """Plaintext of a received payload for passive monitors (verifies, does not
        consume the replay window). None if sealed and undecryptable."""
        from . import md_ts
        return md_ts.open_envelope(self._mdts, keyexpr, payload, check_replay=False)

    def _publish_cmd(self, topic: str, payload: bytes) -> None:
        """Publish a `/cmd` protobuf on `app/<topic>` (sealed when MD-TS is up)."""
        from . import cmd_proto
        from .zenoh_pico import ENC_APPLICATION_PROTOBUF
        self.secure()
        key = cmd_proto.APP_PREFIX + cmd_proto.canonical_topic(topic)
        if self._mdts is not None:
            payload = self._mdts.seal(key, payload)
        self.publisher().put(key, payload, encoding=ENC_APPLICATION_PROTOBUF)

    def publish(self, keyexpr: str, payload, encoding: int = None) -> None:
        """LOW-LEVEL: publish a raw zenoh Put to exactly `keyexpr` with `payload` as
        given (no `app/` prefix, no MD-TS sealing) over reliable UCP channel 3. Use
        `cmd()` / `request()` for `/cmd` topics. Opens the zenoh epoch on first use.

        STATIC/experimental: produces byte-exact Put frames, but a real robot may
        require a full zenoh session and a protobuf payload — see zenoh.py. Refused
        in listen_only mode."""
        if self._refuse_if_listen("publish()"):
            return
        self.publisher().put(keyexpr, payload, encoding=encoding)

    def delete(self, keyexpr: str) -> None:
        """Publish a zenoh Del (undeclare/clear) to a key expression."""
        if self._refuse_if_listen("delete()"):
            return
        self.publisher().delete(keyexpr)

    def cmd(self, topic: str, seq: int = 0, **fields) -> None:
        """Publish a `/cmd/*` command: encodes the recovered protobuf envelope
        (header{seqNum:seq} + data{**fields}) and sends it as a zenoh Put on the
        topic. See freewheel.cmd_proto / native-analysis/cmd-protobuf-schemas.proto
        for each topic's fields. Example:

            robot.cmd("cmd/mission/request", missionId=3, subMode=1)

        STATIC/experimental — schemas are from the app, untested on hardware."""
        if self._refuse_if_listen("cmd()"):
            return
        from . import cmd_proto
        self._publish_cmd(topic, cmd_proto.build_cmd(topic, seq=seq, **fields))

    def request(self, topic: str, timeout: float = 2.0, seq: int = None,
                match_any_seq: Optional[bool] = None, **fields):
        """Request/response `/cmd`: declare a subscriber on the `_rsp` topic, publish
        the `_req` with a seqNum, and wait for the matching response Push (correlated
        by seqNum, or by topic when `match_any_seq=True` as required by `videotrans`
        `/cmd/nm/*` which uses its own TX sequence counter). Returns the decoded
        response `{'seqNum', 'data', 'raw'}`, or None on timeout.

            rsp = robot.request("cmd/common/ping_req")
        """
        if self._refuse_if_listen("request()"):
            return None
        from . import cmd_proto
        canon = cmd_proto.canonical_topic(topic)
        rsp_topic = cmd_proto.response_topic(canon)
        if rsp_topic is None:
            raise ValueError(f"no response topic for {topic!r}")
        if match_any_seq is None:
            match_any_seq = canon.startswith("cmd/nm/")
        self.publisher().open()
        self.secure()
        self._subscribe(cmd_proto.DEVICE_PREFIX + rsp_topic)   # route responses to us
        with self._lock:
            if seq is None:
                seq = self._req_seq
                self._req_seq += 1
            ev = threading.Event()
            key = (rsp_topic, None if match_any_seq else seq)
            self._waiters[key] = {"event": ev, "result": None}
        self._publish_cmd(canon, cmd_proto.build_cmd(canon, seq=seq, **fields))
        got = ev.wait(timeout)
        with self._lock:
            w = self._waiters.pop(key, None)
        return w["result"] if (got and w) else None

    # -- control-bus crypto mode (v1.0.85+; see native-analysis/version-diff-1.0.85.md) --
    def crypto_info(self, timeout: float = 2.0):
        """Query the robot's control-bus crypto mode. Returns the decoded
        `get_crypto_info_rsp` data — ``{'retCode', 'cmdVersion', 'isEncrypted',
        'batchId', 'reserved'}`` — or None.

        v1.0.85+ robots negotiate an optional `secure_v2` layer: the app reads this to
        decide whether to AES-GCM-seal `/cmd` payloads. **is_encrypted=False (or no
        response) means the legacy plaintext path — exactly what this SDK speaks.**
        A v1.0.13 robot has no such topic and simply won't answer → None (= plaintext).
        Run this FIRST on an unknown robot."""
        if self._refuse_if_listen("crypto_info()"):
            return None
        from . import cmd_proto
        if cmd_proto.message_for_topic("cmd/common/get_crypto_info_req") is None:
            return None                       # topic not in the shipped schema
        try:
            rsp = self.request("cmd/common/get_crypto_info_req", timeout=timeout)
        except ValueError:
            return None
        return rsp["data"] if rsp else None

    # -- UWB tracker / follow (see native-analysis/uwb-tracker.md) --------------
    # Follow is computed ON THE ROBOT; these just select a target and toggle the
    # mode over the /cmd bus. Requires a tracker already PAIRED to the robot (a
    # physical step: long-press both power buttons ~5 s). STATIC/experimental —
    # topics are recovered from the app but untested on hardware; refused in
    # listen_only. Pair with freewheel.tracking.TrackingMonitor to read status.
    def follow(self, target_id: int = 1, *, pos=None, target_type: int = None,
               model_version: int = None, request_mode: int = 0, seq: int = 0) -> None:
        """Start follow-me on target `target_id` (optionally set its screen position
        `pos=(x, y)`, the target class `target_type`, and the follow `model_version`
        first). Moves the chassis — unlock + clear space first."""
        if self._refuse_if_listen("follow()"):
            return
        if target_type is not None:
            self.cmd("cmd/tracking/model_switch_cmd", targetType=int(target_type))
        if model_version is not None:
            self.cmd("cmd/tracking/algo_switch_cmd", modelVersion=int(model_version))
        x, y = (pos or (0.0, 0.0))
        self.cmd("cmd/tracking/ctrl_cmd", seq=seq, startTracking=1, selectedId=int(target_id),
                 selectedPosX=float(x), selectedPosY=float(y), requestMode=int(request_mode))

    def stop_follow(self, seq: int = 0) -> None:
        """Stop follow-me (chassis holds)."""
        if self._refuse_if_listen("stop_follow()"):
            return
        self.cmd("cmd/tracking/ctrl_cmd", seq=seq, startTracking=0)

    def list_accessories(self, filter_type: int = 0, timeout: float = 2.0):
        """Request the robot's bound-accessory list (trackers, charging dock).
        Returns the decoded `accessory_list_rsp` (`{seqNum, data, raw}`) or None."""
        return self.request("cmd/common/accessory_list_req", timeout=timeout,
                            filterType=int(filter_type))

    def set_target_type(self, target_type: int, seq: int = 0) -> None:
        """Set the follow target class (e.g. person vs pet — enum TBD on hardware)."""
        if self._refuse_if_listen("set_target_type()"):
            return
        self.cmd("cmd/tracking/model_switch_cmd", seq=seq, targetType=int(target_type))

    def unpair_accessory(self, acc_type: int, sn: bytes, seq: int = 0) -> None:
        """Deactivate/unpair a bound accessory by type + serial number."""
        if self._refuse_if_listen("unpair_accessory()"):
            return
        self.cmd("cmd/common/accessory_deactivate_req", seq=seq, accType=int(acc_type),
                 snLen=len(sn), sn=bytes(sn))

    # -- Device identity & OTA control (`/cmd/robot/sn_req`, `/cmd/ota/*`) ------
    def serial_number(self, sn_type: int = 0, timeout: float = 2.0) -> Optional[str]:
        """Query the robot's serial number via `/cmd/robot/sn_req` (`device_id` for V2 OTA)."""
        if self._refuse_if_listen("serial_number()"):
            return None
        rsp = self.request("cmd/robot/sn_req", timeout=timeout, match_any_seq=True, snType=int(sn_type))
        if not rsp:
            return None
        data = rsp.get("data") or {}
        raw_sn = bytes(data.get("sn") or b"")
        n = int(data.get("lens") or len(raw_sn))
        text = raw_sn[:n].decode("utf-8", errors="replace").rstrip("\x00").strip()
        return text or None

    def ota_control(
        self,
        control_cmd: int,
        *,
        task: Optional[dict] = None,
        timeout: float = 6.0,
    ) -> Optional[dict]:
        """Send `/cmd/ota/upgrade_control_req` (0=START, 1=PAUSE, 2=CANCEL, 3=QUERY, 4=INSTALL)."""
        if self._refuse_if_listen("ota_control()"):
            return None
        fields: dict = {"controlCmd": int(control_cmd)}
        if task is not None:
            fields["task"] = dict(task)
        rsp = self.request("cmd/ota/upgrade_control_req", timeout=timeout, match_any_seq=True, **fields)
        return rsp.get("data") if rsp else None

    # -- Network Manager (`/cmd/nm/wifi_*` Home Wi-Fi provisioning & AP/STA mode) --
    def scan_wifi(self, *, force_scan: bool = True, max_count: int = 32, timeout: float = 8.0) -> list:
        """Ask the robot to scan visible 2.4/5 GHz Wi-Fi access points."""
        if self._refuse_if_listen("scan_wifi()"):
            return []
        rsp = self.request(
            "cmd/nm/wifi_scan_req",
            timeout=timeout,
            forceScan=1 if force_scan else 0,
            maxCount=int(max_count),
            resv=b"\x00" * 6,
        )
        if not rsp:
            return []
        data = rsp.get("data") or {}
        aps = []
        for ap in data.get("aps") or []:
            raw_ssid = bytes(ap.get("ssid") or b"")
            n = int(ap.get("ssidLen") or len(raw_ssid))
            ssid = raw_ssid[:n].decode("utf-8", errors="replace").rstrip("\x00")
            bssid_b = bytes(ap.get("bssid") or b"")
            bssid = ":".join(f"{b:02x}" for b in bssid_b[:6]) if len(bssid_b) >= 6 else ""
            aps.append({
                "ssid": ssid,
                "bssid": bssid,
                "channel": int(ap.get("channel") or 0),
                "rssi": int(ap.get("rssi") or 0),
                "security": int(ap.get("security") or 0),
            })
        return aps

    def provision_wifi(
        self,
        ssid: str,
        password: str = "",
        *,
        security: Optional[int] = None,
        timeout: float = 20.0,
        mqtt_endpoint: str = "",
    ) -> dict:
        """Provision Home Wi-Fi on the robot via the 3-stage `/cmd/nm/wifi_*` commit flow.

        Stages credentials (`wifi_connect_req`), starts a rollback-protected transaction
        (`wifi_provision_start_req`), commits the SoftAP -> Station switch
        (`wifi_provision_commit_req`), and polls `wifi_provision_result_req` until
        the robot either reports `SUCCEEDED(2)`, `FAILED(3)`, or drops SoftAP to join LAN.
        """
        if self._refuse_if_listen("provision_wifi()"):
            raise RuntimeError("cannot provision Wi-Fi in listen_only mode")
        sb = ssid.encode("utf-8")
        pb = password.encode("utf-8")
        if not (1 <= len(sb) <= 32):
            raise ValueError("SSID must be 1..32 UTF-8 bytes")
        if len(pb) > 64:
            raise ValueError("Wi-Fi password must be <= 64 UTF-8 bytes")
        sec = int(security) if security is not None else (2 if pb else 0)
        prov_uuid = os.urandom(16)

        rsp1 = self.request(
            "cmd/nm/wifi_connect_req",
            timeout=4.0,
            ssidLen=len(sb),
            ssid=sb,
            pskLen=len(pb),
            psk=pb,
            security=sec,
            timeoutSec=25,
            uuid=prov_uuid,
            resv=b"\x00" * 4,
        )
        if not rsp1:
            raise RuntimeError("wifi_connect_req timed out")
        r1 = int((rsp1.get("data") or {}).get("result") or 0)
        if r1 != 0:
            raise RuntimeError(f"wifi_connect_req rejected by robot (result={r1})")

        mb = mqtt_endpoint.encode("utf-8")
        rsp2 = self.request(
            "cmd/nm/wifi_provision_start_req",
            timeout=4.0,
            triggerSource=1,
            resv=b"\x00" * 7,
            uuid=prov_uuid,
            mqttEndpointLen=len(mb),
            mqttEndpoint=mb,
            mqttResv=b"\x00" * 7,
        )
        if not rsp2:
            raise RuntimeError("wifi_provision_start_req timed out")
        r2 = int((rsp2.get("data") or {}).get("result") or 0)
        if r2 != 0:
            raise RuntimeError(f"wifi_provision_start_req rejected by robot (result={r2})")

        self._subscribe("device/status/nm/net_online_notify")
        rsp3 = self.request(
            "cmd/nm/wifi_provision_commit_req",
            timeout=4.0,
            triggerSource=1,
            resv=b"\x00" * 7,
            uuid=prov_uuid,
        )
        if rsp3 is not None:
            r3 = int((rsp3.get("data") or {}).get("result") or 0)
            if r3 != 0:
                raise RuntimeError(f"wifi_provision_commit_req rejected by robot (result={r3})")

        fail_names = {
            0: "OK",
            1: "WRONG_KEY",
            2: "NETWORK_NOT_FOUND",
            3: "ASSOC_TIMEOUT",
            4: "DHCP_TIMEOUT",
            5: "WATCHDOG_TIMEOUT",
        }
        deadline = time.monotonic() + max(2.0, timeout)
        missed = 0
        while time.monotonic() < deadline:
            poll = self.request(
                "cmd/nm/wifi_provision_result_req",
                timeout=1.5,
                uuid=prov_uuid,
                resv=b"\x00" * 4,
            )
            if poll is None:
                missed += 1
                if missed >= 3:
                    # Expected on single-radio robots once SoftAP tears down to join STA
                    return {
                        "ok": True,
                        "state": "committed_ap_handoff",
                        "ssid": ssid,
                        "ipv4": "",
                        "uuid_hex": prov_uuid.hex(),
                    }
                continue
            missed = 0
            d = poll.get("data") or {}
            st = int(d.get("state") or 0)
            if st == 2:
                ip_b = bytes(d.get("ipv4") or b"")
                ipv4 = ".".join(str(b) for b in ip_b[:4]) if len(ip_b) >= 4 and any(ip_b[:4]) else ""
                return {
                    "ok": True,
                    "state": "succeeded",
                    "ssid": ssid,
                    "ipv4": ipv4,
                    "channel": int(d.get("channel") or 0),
                    "rssi": int(d.get("rssi") or 0),
                    "uuid_hex": prov_uuid.hex(),
                }
            if st == 3:
                reason = int(d.get("failReason") or 0)
                rname = fail_names.get(reason, f"REASON_{reason}")
                raise RuntimeError(f"Wi-Fi provisioning failed on robot: {rname}")
            time.sleep(0.4)

        return {
            "ok": True,
            "state": "pending",
            "ssid": ssid,
            "ipv4": "",
            "uuid_hex": prov_uuid.hex(),
        }

    def switch_wifi_to_ap(self, *, trigger_source: int = 1, seq: int = 0) -> None:
        """Switch the robot from Home Wi-Fi (Station) back to its SoftAP hotspot (`192.168.7.1`)."""
        if self._refuse_if_listen("switch_wifi_to_ap()"):
            return
        self.cmd("cmd/nm/wifi_switch_to_ap_req", seq=seq, triggerSource=int(trigger_source), resv=b"\x00" * 7)

    def switch_wifi_to_station(self, *, watchdog_sec: int = 30, timeout: float = 4.0) -> Optional[dict]:
        """Switch the robot from SoftAP to its saved Home Wi-Fi Station network."""
        if self._refuse_if_listen("switch_wifi_to_station()"):
            return None
        rsp = self.request(
            "cmd/nm/wifi_switch_to_station_req",
            timeout=timeout,
            triggerSource=1,
            watchdogSec=int(watchdog_sec),
            resv=b"\x00" * 6,
        )
        return rsp.get("data") if rsp else None

    # -- inbound dispatch (user callback + response routing) --------------------
    def _dispatch_rx(self, channel: int, payload: bytes) -> None:
        if self._user_on_message is not None:
            try:
                self._user_on_message(channel, payload)
            except Exception as e:                         # noqa: BLE001
                self._log(f"on_message error: {e!r}")
        if channel in ZENOH_CHANNELS and payload:
            self._route_response(bytes(payload))

    def _route_response(self, payload: bytes) -> None:
        """Feed MD-TS handshake frames to secure(); decrypt + route `/cmd` responses."""
        from .zenoh import ALL_TAGS, iter_frames
        from .zenoh_pico import Put, ZenohPicoDecoder
        from . import cmd_proto, md_ts
        if payload[0] not in ALL_TAGS:
            return
        if self._resp_dec is None:
            self._resp_dec = ZenohPicoDecoder()
        try:
            for fr in iter_frames(payload):
                if not fr.is_data:
                    continue
                for m in self._resp_dec.decode_batch(fr.payload):
                    if not isinstance(m, Put):
                        continue
                    topic = cmd_proto.canonical_topic(m.keyexpr)
                    if topic == md_ts.SECURITY_TOPIC:
                        self._sec_q.put(bytes(m.payload))
                        continue
                    if not self._waiters:
                        continue
                    if self._mdts is not None and md_ts.decode_envelope(m.payload) is None:
                        continue                           # plaintext while encrypted: drop
                    plain = md_ts.open_envelope(self._mdts, m.keyexpr, m.payload)
                    if plain is None:
                        continue
                    try:
                        dec = cmd_proto.decode_cmd(topic, plain)
                    except Exception:                      # noqa: BLE001
                        continue
                    with self._lock:
                        w = (self._waiters.get((topic, dec["seqNum"]))
                             or self._waiters.get((topic, None)))
                        if w is None and dec["seqNum"] == 0:
                            for (wt, _wseq), cand in self._waiters.items():
                                if wt == topic:
                                    w = cand
                                    break
                        if w is not None:
                            w["result"] = dec
                            w["event"].set()
        except Exception:                                  # noqa: BLE001 — never kill RX
            pass

    # -- tx loop -----------------------------------------------------------
    def _tx_loop(self) -> None:
        start = time.monotonic()
        next_tick = start
        while self._running:
            now = time.monotonic()
            try:
                if self._seeding and now - start < SEED_DURATION_S:
                    self._t.send_heartbeat(SEED_PAYLOAD)
                else:
                    if self._seeding:
                        self._seeding = False
                        msg = "seed complete; "
                        msg += "passive (silent) — observing only" if (self.listen_only and self.passive) \
                            else ("streaming SAFE locked heartbeat — observing" if self.listen_only
                                  else "streaming control")
                        self._log(msg)
                    if self.listen_only and self.passive:
                        self._t.auto_ack = False    # fully silent: no acks either; just keep RX alive
                    else:
                        with self._lock:
                            payload = self.state.to_bytes()   # locked+paused in listen_only
                        self._t.send_heartbeat(payload)
            except OSError as e:
                if self._running:
                    self._t.link_dead = True
                    self._log(f"TX socket error: {e}")
                break
            next_tick += HEARTBEAT_INTERVAL_S
            sleep = next_tick - time.monotonic()
            if sleep > 0:
                time.sleep(sleep)
            else:
                next_tick = time.monotonic()   # fell behind; resync cadence
