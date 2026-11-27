"""Bluetooth Low Energy (BLE) pairing, SoftAP wake, and Wi-Fi onboarding for Beni.

Stock Beni robots sleep their Wi-Fi radio or run an isolated SoftAP (`192.168.7.1`)
until woken/paired over BLE GATT service `0000FFF0` (`char0=FFF1` write-without-rsp,
`char1=FFF2` read, `char2=FFF3` notify).

Wire layers implemented here (zero external SDK dependency):
  1. V0 BLE stream framing: `[0x55 SOF][u8 total_len][u8 flags][u8 cmd_id][payload][u8 crc8]`
     where `crc8` is CRC-8/AUTOSAR (`poly=0x2F, init=0x99, xor_out=0x00`) and
     `flags=0x04` marks an `MD-TS` AEAD record (or legacy V0 response).
  2. BLE `MD-TS` (`transport = 1`) static X25519 pairing + session handshake:
       `0x55` C->S `CLIENT_HELLO(1)` -> (`0x56` `PENDING_BUTTON(3)` while user holds
       robot button 3-5 s) -> `0x56` `SERVER_HELLO(2)` -> `4 -> 5 -> 6 -> 7` with
       35-byte BLE AAD (`MD-TS-AAD\\0\\x01\\x01\\x01[dir]\\x01[chid:8][seq:8][ble_hdr:4]`).
     Saves client + robot static keys to `~/.config/freewheel/identity.json` (`0600`).
  3. BLE network opcodes (sealed under `MD-TS` `seq >= 1`):
       `0x53 -> 0x54` regulatory country sync (`b"US"`, etc.)
       `0x50 -> 0x51` SoftAP credentials (`[u8 ssid_len][ssid][u8 psk_len][psk]`)

`bleak` is imported lazily only when scanning or connecting real BLE hardware, so
unit tests, the SITL simulator (`SimBlePeripheral`), and UDP-only SDK callers have
zero mandatory `bleak` dependency.

CLI:
  python -m freewheel.ble scan
  python -m freewheel.ble pair [--country US]
  python -m freewheel.ble setup-wifi --ssid MyHomeWifi --password secret [--switch-os-wifi]
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
import getpass
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Callable, List, Optional, Sequence, Tuple

from . import md_ts

# ── BLE GATT UUIDs & opcodes ─────────────────────────────────────────────────
BLE_SERVICE_UUID = "0000fff0-0000-1000-8000-00805f9b34fb"
BLE_ALT_SERVICE_UUID = "0100fff0-0000-1000-8000-00805f9b34fb"
BLE_WRITE_CHAR_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
BLE_READ_CHAR_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"
BLE_NOTIFY_CHAR_UUID = "0000fff3-0000-1000-8000-00805f9b34fb"
BLE_MANUFACTURER_ID = 0xFFFE
BENI_NAME_PREFIXES = ("Beni-", "BeniLite-")

BLE_SOF = 0x55
BLE_FLAG_PLAIN = 0x00
BLE_FLAG_MD_TS = 0x04
BLE_MIN_FRAME_LEN = 5
BLE_MAX_FRAME_LEN = 255
BLE_MAX_PAYLOAD_LEN = 250

CMD_WIFI_CRED_REQ = 0x50
CMD_WIFI_CRED_RSP = 0x51
CMD_COUNTRY_SYNC_REQ = 0x53
CMD_COUNTRY_SYNC_RSP = 0x54
CMD_MD_TS_CLIENT = 0x55
CMD_MD_TS_SERVER = 0x56

SOFTAP_DEFAULT_HOST = "192.168.7.1"
SOFTAP_DEFAULT_PORT = 9007

PENDING_WAITING_BUTTON = 0x01
PENDING_AUTH_BUSY = 0x03


class BleError(RuntimeError):
    def __init__(self, code: str, message: str, hint: str = ""):
        super().__init__(f"{code}: {message}" + (f" ({hint})" if hint else ""))
        self.code = code
        self.hint = hint


# ── CRC-8/AUTOSAR + V0 stream framing ────────────────────────────────────────
def _make_crc8_autosar_table() -> Tuple[int, ...]:
    tbl = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x2F) & 0xFF if (crc & 0x80) else ((crc << 1) & 0xFF)
        tbl.append(crc)
    return tuple(tbl)


_CRC8_TABLE = _make_crc8_autosar_table()


def crc8_autosar(data: bytes) -> int:
    """CRC-8/AUTOSAR (`poly=0x2F, init=0x99, refin=false, refout=false, xorout=0x00`)."""
    crc = 0x99
    for b in data:
        crc = _CRC8_TABLE[(crc ^ b) & 0xFF]
    return crc


@dataclass(frozen=True)
class BleFrame:
    cmd_id: int
    flags: int
    payload: bytes

    @property
    def header(self) -> bytes:
        return bytes([BLE_SOF, (BLE_MIN_FRAME_LEN + len(self.payload)) & 0xFF,
                      self.flags & 0xFF, self.cmd_id & 0xFF])


def encode_ble_frame(cmd_id: int, payload: bytes = b"", *, flags: int = BLE_FLAG_PLAIN) -> bytes:
    body = bytes(payload)
    if len(body) > BLE_MAX_PAYLOAD_LEN:
        raise BleError("FRAME_TOO_LARGE", f"BLE payload {len(body)} B > {BLE_MAX_PAYLOAD_LEN}")
    if (flags & 0xFB) != 0:
        raise BleError("BAD_FLAGS", f"unsupported BLE flags 0x{flags:02X}")
    total_len = BLE_MIN_FRAME_LEN + len(body)
    wo_crc = bytes([BLE_SOF, total_len, flags & 0xFF, cmd_id & 0xFF]) + body
    return wo_crc + bytes([crc8_autosar(wo_crc)])


def decode_ble_frame(raw: bytes) -> BleFrame:
    d = bytes(raw)
    if len(d) < BLE_MIN_FRAME_LEN or d[0] != BLE_SOF:
        raise BleError("BAD_FRAME", "missing 0x55 SOF or truncated BLE frame")
    total_len = d[1]
    if total_len != len(d) or total_len < BLE_MIN_FRAME_LEN:
        raise BleError("BAD_LENGTH", f"BLE frame total_len={total_len} != actual={len(d)}")
    flags, cmd_id = d[2], d[3]
    if (flags & 0xFB) != 0:
        raise BleError("BAD_FLAGS", f"invalid BLE frame flags 0x{flags:02X}")
    want_crc = crc8_autosar(d[:-1])
    if d[-1] != want_crc:
        raise BleError("BAD_CRC", f"CRC-8 mismatch: got 0x{d[-1]:02X}, expected 0x{want_crc:02X}")
    return BleFrame(cmd_id=cmd_id, flags=flags, payload=d[4:-1])


class BleStreamParser:
    """Reassemble V0 BLE frames across arbitrary ATT MTU notification chunks."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.crc_errors = 0
        self.resyncs = 0

    def reset(self) -> None:
        self._buf.clear()

    def push(self, chunk: bytes) -> List[BleFrame]:
        if chunk:
            self._buf.extend(chunk)
        out: List[BleFrame] = []
        while len(self._buf) >= 1:
            if self._buf[0] != BLE_SOF:
                idx = self._buf.find(bytes([BLE_SOF]), 1)
                self.resyncs += 1
                if idx < 0:
                    self._buf.clear()
                    break
                del self._buf[:idx]
            if len(self._buf) < 4:
                break
            total_len = self._buf[1]
            flags = self._buf[2]
            if total_len < BLE_MIN_FRAME_LEN or (flags & 0xFB) != 0:
                self.resyncs += 1
                del self._buf[:1]
                continue
            if len(self._buf) < total_len:
                break
            candidate = bytes(self._buf[:total_len])
            if crc8_autosar(candidate[:-1]) != candidate[-1]:
                self.crc_errors += 1
                self.resyncs += 1
                del self._buf[:1]
                continue
            del self._buf[:total_len]
            out.append(BleFrame(cmd_id=candidate[3], flags=flags, payload=candidate[4:-1]))
        return out


# ── SoftAP & Country Code Payload Codecs ─────────────────────────────────────
@dataclass(frozen=True)
class SoftApCredentials:
    ssid: str
    password: str
    host: str = SOFTAP_DEFAULT_HOST
    port: int = SOFTAP_DEFAULT_PORT
    security_mode: str = "md-ts"
    country_synced: Optional[str] = None


def encode_softap_payload(ssid: str, password: str) -> bytes:
    sb = ssid.encode("utf-8")
    pb = password.encode("utf-8")
    if not (1 <= len(sb) <= 32) or len(pb) > 64:
        raise BleError("BAD_WIFI_CRED", "invalid SoftAP SSID or password length")
    return bytes([len(sb)]) + sb + bytes([len(pb)]) + pb


def decode_softap_payload(payload: bytes) -> Tuple[str, str]:
    d = bytes(payload)
    if len(d) < 2:
        raise BleError("BAD_WIFI_CRED", f"SoftAP payload too short ({len(d)} B)")
    ssid_len = d[0]
    if 1 + ssid_len >= len(d):
        raise BleError("BAD_WIFI_CRED", "SoftAP SSID length overruns BLE payload")
    ssid_raw = d[1:1 + ssid_len]
    psk_len = d[1 + ssid_len]
    end = 2 + ssid_len + psk_len
    if end > len(d):
        raise BleError("BAD_WIFI_CRED", "SoftAP password length overruns BLE payload")
    psk_raw = d[2 + ssid_len:end]
    try:
        ssid = ssid_raw.decode("utf-8").rstrip("\x00")
        password = psk_raw.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError as e:
        raise BleError("BAD_WIFI_CRED", "SoftAP credentials are not valid UTF-8") from e
    if not ssid:
        raise BleError("BAD_WIFI_CRED", "robot returned empty SoftAP SSID")
    return ssid, password


def normalize_country_code(country: Optional[str]) -> Optional[bytes]:
    if not country:
        return None
    cc = country.strip().upper()
    if len(cc) != 2 or not cc.isascii() or not cc.isalpha():
        raise BleError("BAD_COUNTRY", f"country code must be 2 ASCII letters (e.g. 'US'), got {country!r}")
    return cc.encode("ascii")


# ── BLE Advertisement Matching ───────────────────────────────────────────────
@dataclass(frozen=True)
class BleDeviceInfo:
    address: str
    name: str
    rssi: Optional[int] = None
    pairing_mode: bool = False
    manufacturer_hex: str = ""
    simulated: bool = False

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "pairing_mode": self.pairing_mode,
            "manufacturer_hex": self.manufacturer_hex,
            "simulated": self.simulated,
        }


def match_beni_advertisement(
    *,
    address: str,
    name: str = "",
    service_uuids: Sequence[str] = (),
    manufacturer_data: Optional[dict] = None,
    rssi: Optional[int] = None,
) -> Optional[BleDeviceInfo]:
    uuids = {u.lower() for u in (service_uuids or ())}
    mfg = manufacturer_data or {}
    mfg_bytes = mfg.get(BLE_MANUFACTURER_ID, b"")
    has_service = BLE_SERVICE_UUID in uuids or BLE_ALT_SERVICE_UUID in uuids
    has_prefix = any((name or "").startswith(p) for p in BENI_NAME_PREFIXES)
    has_mfg = (BLE_MANUFACTURER_ID in mfg) and (not name or name.lower().startswith("beni"))
    if not (has_service or has_prefix or has_mfg):
        return None
    pairing_mode = len(mfg_bytes) >= 3 and mfg_bytes[2] == 1
    return BleDeviceInfo(
        address=str(address),
        name=name or f"Beni-{str(address)[-5:].replace(':', '')}",
        rssi=rssi,
        pairing_mode=pairing_mode,
        manufacturer_hex=bytes(mfg_bytes).hex(),
    )


# ── Simulated BLE Peripheral (SITL + hardware-free testing) ──────────────────
class SimBlePeripheral:
    """In-memory robot BLE GATT `0000FFF0` responder implementing V0 + `MD-TS` (`transport=1`).

    Fragments outgoing notifications into `mtu_payload` chunks (default 20 bytes, matching
    BLE 4.0 `ATT_MTU=23`) and enforces the 3-5 s physical button-hold gate unless the
    client's `client_id` is already in `authorized`.
    """

    def __init__(
        self,
        *,
        address: str = "AA:BB:CC:DD:EE:01",
        name: str = "Beni-SIM001",
        ssid: str = "Beni-SIM001",
        password: str = "sim-beni-pass",
        robot_private_key: Optional[bytes] = None,
        authorized: Optional[dict] = None,
        require_md_ts: bool = True,
        busy: bool = False,
        mtu_payload: int = 20,
    ) -> None:
        self.address = address
        self.name = name
        self.ssid = ssid
        self.password = password
        self._private_key: Optional[bytes] = robot_private_key
        self._public_key: Optional[bytes] = None
        self.authorized = dict(authorized or {})     # client_id -> client_pub
        self.require_md_ts = require_md_ts
        self.busy = busy
        self.mtu_payload = max(1, int(mtu_payload))
        self.country_code = "US"

        self._rx_parser = BleStreamParser()
        self._notify_cb: Optional[Callable[[bytes], None]] = None
        self._awaiting_client: Optional[Tuple[bytes, int, bytes]] = None  # (cid, kv, cpub)
        self._pending_hs: Optional[Tuple[md_ts.HsMessage, md_ts.Session]] = None
        self.session: Optional[md_ts.Session] = None
        self._lock = threading.Lock()

    @property
    def private_key(self) -> bytes:
        if self._private_key is None:
            self._private_key = md_ts.random_nonzero(32)
        return self._private_key

    @property
    def public_key(self) -> bytes:
        if self._public_key is None:
            self._public_key = md_ts.x25519_public(self.private_key)
        return self._public_key

    def advertisement(self) -> BleDeviceInfo:
        with self._lock:
            pairing = self._awaiting_client is not None
        return BleDeviceInfo(
            address=self.address,
            name=self.name,
            rssi=-46,
            pairing_mode=pairing,
            manufacturer_hex="010001" if pairing else "010000",
            simulated=True,
        )

    @property
    def awaiting_button(self) -> bool:
        with self._lock:
            return self._awaiting_client is not None

    def set_notify_callback(self, cb: Optional[Callable[[bytes], None]]) -> None:
        with self._lock:
            self._notify_cb = cb

    def _emit_frame(self, frame_bytes: bytes) -> None:
        cb = self._notify_cb
        if cb is None:
            return
        step = self.mtu_payload
        for i in range(0, len(frame_bytes), step):
            cb(frame_bytes[i:i + step])

    def press_button(self) -> bool:
        """Simulate holding the robot's physical pairing button for 3-5 seconds."""
        reply: Optional[bytes] = None
        with self._lock:
            if self._awaiting_client is None:
                return False
            cid, kv, cpub = self._awaiting_client
            self.authorized[cid] = cpub
            self._awaiting_client = None
            hs = md_ts.build_server_hello(cid, kv, self.public_key)
            reply = encode_ble_frame(CMD_MD_TS_SERVER, hs, flags=BLE_FLAG_PLAIN)
        if reply is not None:
            self._emit_frame(reply)
        return True

    def write_char0(self, data: bytes) -> None:
        replies: List[bytes] = []
        with self._lock:
            for frame in self._rx_parser.push(data):
                out = self._handle_frame_locked(frame)
                if out is not None:
                    replies.append(out)
        for r in replies:
            self._emit_frame(r)

    def _handle_frame_locked(self, frame: BleFrame) -> Optional[bytes]:
        if frame.cmd_id == CMD_MD_TS_CLIENT:
            if frame.flags == BLE_FLAG_PLAIN:
                try:
                    msg = md_ts.parse_hs(frame.payload)
                except ValueError:
                    return None
                if msg.msg_type == md_ts.HS_CLIENT_HELLO:
                    if self.busy:
                        return encode_ble_frame(
                            CMD_MD_TS_SERVER,
                            md_ts.build_pending_button(msg.client_id, msg.key_version, PENDING_AUTH_BUSY),
                            flags=BLE_FLAG_PLAIN,
                        )
                    known_pub = self.authorized.get(msg.client_id)
                    if known_pub is not None:
                        if known_pub != msg.public_key:
                            return encode_ble_frame(
                                CMD_MD_TS_SERVER,
                                md_ts.build_error(msg.client_id, msg.key_version, md_ts.ERR_PUBKEY_MISMATCH),
                                flags=BLE_FLAG_PLAIN,
                            )
                        return encode_ble_frame(
                            CMD_MD_TS_SERVER,
                            md_ts.build_server_hello(msg.client_id, msg.key_version, self.public_key),
                            flags=BLE_FLAG_PLAIN,
                        )
                    self._awaiting_client = (msg.client_id, msg.key_version, msg.public_key)
                    return encode_ble_frame(
                        CMD_MD_TS_SERVER,
                        md_ts.build_pending_button(msg.client_id, msg.key_version, PENDING_WAITING_BUTTON),
                        flags=BLE_FLAG_PLAIN,
                    )
                if msg.msg_type == md_ts.HS_SESSION_START:
                    if self._awaiting_client is not None and self._awaiting_client[0] == msg.client_id:
                        return encode_ble_frame(
                            CMD_MD_TS_SERVER,
                            md_ts.build_error(msg.client_id, msg.key_version, md_ts.ERR_PENDING_NOT_FINALIZED),
                            flags=BLE_FLAG_PLAIN,
                        )
                    pub = self.authorized.get(msg.client_id)
                    if pub is None:
                        return encode_ble_frame(
                            CMD_MD_TS_SERVER,
                            md_ts.build_error(msg.client_id, msg.key_version, md_ts.ERR_UNAUTHORIZED),
                            flags=BLE_FLAG_PLAIN,
                        )
                    snonce = md_ts.random_nonzero(32)
                    chid = md_ts.random_nonzero(8)
                    sess = md_ts.Session.from_handshake(
                        role=md_ts.ROLE_SERVER,
                        transport=md_ts.TRANSPORT_BLE,
                        private_key=self.private_key,
                        peer_public_key=pub,
                        client_id=msg.client_id,
                        key_version=msg.key_version,
                        client_pub=pub,
                        robot_pub=self.public_key,
                        client_nonce=msg.nonce,
                        server_nonce=snonce,
                        channel_id=chid,
                    )
                    self._pending_hs = (msg, sess)
                    self.session = None
                    return encode_ble_frame(
                        CMD_MD_TS_SERVER,
                        md_ts.build_session_challenge(msg.client_id, msg.key_version, snonce, chid),
                        flags=BLE_FLAG_PLAIN,
                    )
                return None

            if frame.flags == BLE_FLAG_MD_TS and self._pending_hs is not None:
                msg, sess = self._pending_hs
                try:
                    sess.open_ble_confirm(frame.payload, msg.client_id, msg.key_version, frame.header)
                except md_ts.MdTsError:
                    return encode_ble_frame(
                        CMD_MD_TS_SERVER,
                        md_ts.build_error(msg.client_id, msg.key_version, md_ts.ERR_CONFIRM_FAILED),
                        flags=BLE_FLAG_PLAIN,
                    )
                self._pending_hs = None
                self.session = sess
                rec = sess.seal_ble_confirm(msg.client_id, msg.key_version, CMD_MD_TS_SERVER)
                return encode_ble_frame(CMD_MD_TS_SERVER, rec, flags=BLE_FLAG_MD_TS)
            return None

        # Application commands (0x50 SoftAP query, 0x53 Country sync)
        if frame.flags == BLE_FLAG_MD_TS:
            if self.session is None or not self.session.confirmed:
                return None
            try:
                pt = self.session.open_ble(frame.cmd_id, frame.flags, frame.payload)
            except md_ts.MdTsError:
                return None
            rsp_cmd, rsp_pt = self._dispatch_app_cmd(frame.cmd_id, pt)
            if rsp_cmd is None:
                return None
            return encode_ble_frame(rsp_cmd, self.session.seal_ble(rsp_cmd, rsp_pt), flags=BLE_FLAG_MD_TS)

        if self.require_md_ts:
            return None
        rsp_cmd, rsp_pt = self._dispatch_app_cmd(frame.cmd_id, frame.payload)
        if rsp_cmd is None:
            return None
        return encode_ble_frame(rsp_cmd, rsp_pt, flags=BLE_FLAG_MD_TS)

    def _dispatch_app_cmd(self, cmd_id: int, pt: bytes) -> Tuple[Optional[int], bytes]:
        if cmd_id == CMD_COUNTRY_SYNC_REQ:
            if len(pt) >= 2:
                self.country_code = pt[:2].decode("ascii", errors="ignore") or self.country_code
                return CMD_COUNTRY_SYNC_RSP, b"\x00"
            return CMD_COUNTRY_SYNC_RSP, b"\x01"
        if cmd_id == CMD_WIFI_CRED_REQ:
            return CMD_WIFI_CRED_RSP, encode_softap_payload(self.ssid, self.password)
        return None, b""


# ── GATT Transport Abstraction (Sim or lazy `bleak`) ─────────────────────────
class _SimGattLink:
    def __init__(self, peripheral: SimBlePeripheral) -> None:
        self.peripheral = peripheral
        self._parser = BleStreamParser()
        self._rx_q: "queue.Queue[BleFrame]" = queue.Queue()
        self.address = peripheral.address
        self.name = peripheral.name

    def open(self) -> None:
        def _on_chunk(chunk: bytes) -> None:
            for frame in self._parser.push(chunk):
                self._rx_q.put(frame)

        self.peripheral.set_notify_callback(_on_chunk)

    def close(self) -> None:
        self.peripheral.set_notify_callback(None)

    def drain(self) -> None:
        while True:
            try:
                self._rx_q.get_nowait()
            except queue.Empty:
                return

    def send_frame(self, frame_bytes: bytes) -> None:
        self.peripheral.write_char0(frame_bytes)

    def recv_frame(self, timeout: float) -> Optional[BleFrame]:
        try:
            return self._rx_q.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None


def _require_bleak():
    try:
        import bleak  # type: ignore
        return bleak
    except ImportError as e:
        raise BleError(
            "BLEAK_NOT_INSTALLED",
            "Python BLE library `bleak` is required for physical Bluetooth hardware",
            "install with `pip install bleak`",
        ) from e


class _BleakGattLink:
    """Synchronous wrapper running `bleak.BleakClient` on a dedicated background event loop."""

    def __init__(self, device_or_address: str, *, name: str = "", connect_timeout: float = 12.0) -> None:
        self._target = device_or_address
        self.address = str(getattr(device_or_address, "address", device_or_address))
        self.name = name or str(getattr(device_or_address, "name", "") or "")
        self._connect_timeout = connect_timeout
        self._parser = BleStreamParser()
        self._rx_q: "queue.Queue[BleFrame]" = queue.Queue()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._client = None

    def open(self) -> None:
        bleak = _require_bleak()
        ready = threading.Event()
        err_box: List[BaseException] = []

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            try:
                loop.run_until_complete(self._async_open(bleak))
            except BaseException as exc:
                err_box.append(exc)
                ready.set()
                loop.close()
                return
            ready.set()
            try:
                loop.run_forever()
            finally:
                try:
                    loop.run_until_complete(self._async_close())
                except Exception:
                    pass
                loop.close()

        self._thread = threading.Thread(target=_runner, name="freewheel-bleak", daemon=True)
        self._thread.start()
        ready.wait(timeout=self._connect_timeout + 5.0)
        if err_box:
            raise BleError("BLE_CONNECT_FAILED", f"could not connect to {self.address}: {err_box[0]}")
        if self._client is None:
            raise BleError("BLE_CONNECT_TIMEOUT", f"timed out connecting to {self.address}")

    async def _async_open(self, bleak) -> None:
        client = bleak.BleakClient(self._target, timeout=self._connect_timeout)
        await client.connect()

        def _notify_cb(_sender, data: bytearray) -> None:
            for frame in self._parser.push(bytes(data)):
                self._rx_q.put(frame)

        await client.start_notify(BLE_NOTIFY_CHAR_UUID, _notify_cb)
        self._client = client

    async def _async_close(self) -> None:
        c = self._client
        self._client = None
        if c is not None:
            try:
                await c.stop_notify(BLE_NOTIFY_CHAR_UUID)
            except Exception:
                pass
            try:
                await c.disconnect()
            except Exception:
                pass

    def close(self) -> None:
        loop = self._loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self._loop = None
        self._thread = None

    def drain(self) -> None:
        while True:
            try:
                self._rx_q.get_nowait()
            except queue.Empty:
                return

    def send_frame(self, frame_bytes: bytes) -> None:
        loop = self._loop
        client = self._client
        if loop is None or client is None or not loop.is_running():
            raise BleError("BLE_DISCONNECTED", "BLE GATT client is not connected")
        fut = asyncio.run_coroutine_threadsafe(
            client.write_gatt_char(BLE_WRITE_CHAR_UUID, frame_bytes, response=False),
            loop,
        )
        try:
            fut.result(timeout=5.0)
        except Exception as e:
            raise BleError("BLE_WRITE_FAILED", f"BLE write failed: {e}") from e

    def recv_frame(self, timeout: float) -> Optional[BleFrame]:
        try:
            return self._rx_q.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None


# ── BLE Scanning + Pairing + SoftAP Wake ─────────────────────────────────────
def scan_ble(
    *,
    timeout: float = 5.0,
    sim_peripheral: Optional[SimBlePeripheral] = None,
) -> List[BleDeviceInfo]:
    """Scan for nearby Beni robots over BLE (or return the simulated robot if given)."""
    if sim_peripheral is not None:
        return [sim_peripheral.advertisement()]
    bleak = _require_bleak()

    async def _scan() -> List[BleDeviceInfo]:
        discovered = await bleak.BleakScanner.discover(timeout=timeout, return_adv=True)
        found: List[BleDeviceInfo] = []
        for _key, (dev, adv) in discovered.items():
            info = match_beni_advertisement(
                address=getattr(dev, "address", ""),
                name=getattr(adv, "local_name", None) or getattr(dev, "name", None) or "",
                service_uuids=getattr(adv, "service_uuids", None) or (),
                manufacturer_data=getattr(adv, "manufacturer_data", None) or {},
                rssi=getattr(adv, "rssi", None),
            )
            if info is not None:
                found.append(info)
        found.sort(key=lambda d: (not d.pairing_mode, -(d.rssi if d.rssi is not None else -999), d.name))
        return found

    return asyncio.run(_scan())


@dataclass
class BlePairingResult:
    device: BleDeviceInfo
    softap: SoftApCredentials
    identity_path: str
    client_id_hex: str
    robot_public_key_hex: str
    button_held: bool = False

    def to_dict(self) -> dict:
        return {
            "device": self.device.to_dict(),
            "ssid": self.softap.ssid,
            "password": self.softap.password,
            "softap_host": self.softap.host,
            "softap_port": self.softap.port,
            "security_mode": self.softap.security_mode,
            "country_synced": self.softap.country_synced,
            "identity_path": self.identity_path,
            "client_id_hex": self.client_id_hex,
            "robot_public_key_hex": self.robot_public_key_hex,
            "button_held": self.button_held,
        }


def _recv_matching(
    link,
    predicate: Callable[[BleFrame], bool],
    timeout: float,
) -> Optional[BleFrame]:
    deadline = time.monotonic() + timeout
    while True:
        rem = deadline - time.monotonic()
        if rem <= 0:
            return None
        frame = link.recv_frame(min(0.2, rem))
        if frame is not None and predicate(frame):
            return frame


def pair_and_get_softap(
    *,
    device: Optional[str] = None,
    scan_timeout: float = 5.0,
    button_timeout: float = 35.0,
    country_code: Optional[str] = "US",
    identity_path: Optional[str] = None,
    allow_key_change: bool = False,
    allow_v0_fallback: bool = False,
    sim_peripheral: Optional[SimBlePeripheral] = None,
    on_stage: Optional[Callable[[str, str], None]] = None,
    on_awaiting_button: Optional[Callable[[BleDeviceInfo], None]] = None,
) -> BlePairingResult:
    """Pair X25519 identity over BLE (`MD-TS` `transport=1`), wake SoftAP, and return credentials.

    Automatically creates `~/.config/freewheel/identity.json` on first run and saves the
    robot's static X25519 public key there (`0600`) so `MondoClient` connects with zero
    external tools.
    """
    def _stage(stage: str, detail: str = "") -> None:
        if on_stage is not None:
            on_stage(stage, detail)

    cc_bytes = normalize_country_code(country_code)
    ident = md_ts.Identity.load_or_create(identity_path)

    if sim_peripheral is not None:
        dev_info = sim_peripheral.advertisement()
        link = _SimGattLink(sim_peripheral)
    else:
        _stage("scanning", "Scanning for Beni over Bluetooth...")
        devices = scan_ble(timeout=scan_timeout)
        if device:
            needle = device.strip().lower()
            matches = [
                d for d in devices
                if d.address.lower() == needle or d.name.lower() == needle or needle in d.name.lower()
            ]
            if matches:
                dev_info = matches[0]
            else:
                dev_info = BleDeviceInfo(address=device.strip(), name=device.strip())
        else:
            if not devices:
                raise BleError(
                    "NO_ROBOT_FOUND",
                    "no Beni robot found over Bluetooth",
                    "power on the robot and bring this machine within ~3 m",
                )
            dev_info = devices[0]
        link = _BleakGattLink(dev_info.address, name=dev_info.name)

    _stage("connecting", f"Connecting to {dev_info.name} ({dev_info.address})...")
    link.open()
    button_held = False
    try:
        link.drain()
        # 1. CLIENT_HELLO(1) -> [PENDING_BUTTON(3) -> hold button] -> SERVER_HELLO(2)
        hello = encode_ble_frame(
            CMD_MD_TS_CLIENT,
            md_ts.build_client_hello(ident.client_id, ident.key_version, ident.public_key),
            flags=BLE_FLAG_PLAIN,
        )
        link.send_frame(hello)
        first = _recv_matching(
            link,
            lambda f: f.cmd_id == CMD_MD_TS_SERVER and f.flags == BLE_FLAG_PLAIN,
            timeout=2.0,
        )

        sess: Optional[md_ts.Session] = None
        robot_pub: Optional[bytes] = None

        if first is None:
            if not allow_v0_fallback:
                raise BleError(
                    "BLE_HANDSHAKE_TIMEOUT",
                    "robot did not respond to BLE MD-TS CLIENT_HELLO",
                    "wake the robot and ensure Bluetooth is in range",
                )
        else:
            msg = md_ts.parse_hs(first.payload)
            if msg.client_id != ident.client_id:
                raise BleError("BLE_CLIENT_ID_MISMATCH", "unexpected client_id in BLE handshake reply")
            if msg.msg_type == md_ts.HS_ERROR:
                raise BleError(msg.error_name, "robot rejected BLE CLIENT_HELLO")

            if msg.msg_type == md_ts.HS_PENDING_BUTTON:
                if msg.pending_status == PENDING_AUTH_BUSY:
                    raise BleError(
                        "BLE_AUTH_BUSY",
                        "robot is currently pairing with another Bluetooth client",
                        "wait a few seconds and retry",
                    )
                button_held = True
                _stage(
                    "awaiting_button",
                    f"Hold the physical button on {dev_info.name} for 3-5 seconds to authorize pairing...",
                )
                if on_awaiting_button is not None:
                    on_awaiting_button(dev_info)
                deadline = time.monotonic() + button_timeout
                last_resend = time.monotonic()
                msg = None
                while time.monotonic() < deadline:
                    now = time.monotonic()
                    if now - last_resend >= 1.0:
                        link.send_frame(hello)
                        last_resend = now
                    frm = _recv_matching(
                        link,
                        lambda f: f.cmd_id == CMD_MD_TS_SERVER and f.flags == BLE_FLAG_PLAIN,
                        timeout=0.25,
                    )
                    if frm is None:
                        continue
                    cand = md_ts.parse_hs(frm.payload)
                    if cand.client_id != ident.client_id:
                        continue
                    if cand.msg_type == md_ts.HS_PENDING_BUTTON:
                        if cand.pending_status == PENDING_AUTH_BUSY:
                            raise BleError("BLE_AUTH_BUSY", "robot BLE pairing became busy")
                        continue
                    if cand.msg_type == md_ts.HS_ERROR:
                        raise BleError(cand.error_name, "robot rejected BLE button authorization")
                    if cand.msg_type == md_ts.HS_SERVER_HELLO:
                        msg = cand
                        break
                if msg is None:
                    raise BleError(
                        "BUTTON_TIMEOUT",
                        f"timed out after {button_timeout:.0f}s waiting for the 3-5 s robot button hold",
                    )

            if msg.msg_type != md_ts.HS_SERVER_HELLO:
                raise BleError("BLE_BAD_HANDSHAKE", f"expected SERVER_HELLO(2), got msg_type={msg.msg_type}")

            robot_pub = msg.public_key
            pinned = ident.lookup_robot_key(
                ble_address=dev_info.address,
                device_name=dev_info.name,
                allow_default=False,
            )
            if pinned is not None and pinned != robot_pub and not allow_key_change:
                raise BleError(
                    "ROBOT_KEY_CHANGED",
                    f"robot {dev_info.name} ({dev_info.address}) presented a different X25519 public key",
                    "pass allow_key_change=True / --allow-key-change only after factory reset",
                )

            # Persist robot key immediately once button hold / SERVER_HELLO succeeds
            ident.remember_robot(robot_pub, ble_address=dev_info.address, device_name=dev_info.name)
            ident.save(identity_path)

            # 2. SESSION_START(4) -> SESSION_CHALLENGE(5)
            _stage("handshaking", "Deriving BLE MD-TS session keys...")
            link.drain()
            cnonce = md_ts.random_nonzero(32)
            link.send_frame(
                encode_ble_frame(
                    CMD_MD_TS_CLIENT,
                    md_ts.build_session_start(ident.client_id, ident.key_version, cnonce),
                    flags=BLE_FLAG_PLAIN,
                )
            )
            chal_frm = _recv_matching(
                link,
                lambda f: f.cmd_id == CMD_MD_TS_SERVER and f.flags == BLE_FLAG_PLAIN,
                timeout=3.0,
            )
            if chal_frm is None:
                raise BleError("BLE_CHALLENGE_TIMEOUT", "timed out waiting for BLE SESSION_CHALLENGE(5)")
            chal = md_ts.parse_hs(chal_frm.payload)
            if chal.msg_type == md_ts.HS_ERROR:
                raise BleError(chal.error_name, "robot rejected BLE SESSION_START(4)")
            if chal.msg_type != md_ts.HS_SESSION_CHALLENGE:
                raise BleError("BLE_BAD_HANDSHAKE", f"expected SESSION_CHALLENGE(5), got {chal.msg_type}")

            sess = md_ts.Session.from_handshake(
                role=md_ts.ROLE_CLIENT,
                transport=md_ts.TRANSPORT_BLE,
                private_key=ident.private_key,
                peer_public_key=robot_pub,
                client_id=ident.client_id,
                key_version=ident.key_version,
                client_pub=ident.public_key,
                robot_pub=robot_pub,
                client_nonce=cnonce,
                server_nonce=chal.nonce,
                channel_id=chal.channel_id,
            )

            # 3. CLIENT_CONFIRM(6) -> SERVER_CONFIRM(7)
            link.drain()
            c_rec = sess.seal_ble_confirm(ident.client_id, ident.key_version, CMD_MD_TS_CLIENT)
            link.send_frame(encode_ble_frame(CMD_MD_TS_CLIENT, c_rec, flags=BLE_FLAG_MD_TS))
            sc_frm = _recv_matching(
                link,
                lambda f: f.cmd_id == CMD_MD_TS_SERVER,
                timeout=3.0,
            )
            if sc_frm is None:
                raise BleError("BLE_CONFIRM_TIMEOUT", "timed out waiting for BLE SERVER_CONFIRM(7)")
            if sc_frm.flags == BLE_FLAG_PLAIN:
                err_hs = md_ts.parse_hs(sc_frm.payload)
                raise BleError(err_hs.error_name, "robot rejected BLE CLIENT_CONFIRM(6)")
            sess.open_ble_confirm(sc_frm.payload, ident.client_id, ident.key_version, sc_frm.header)

        # 4. Optional Country Sync (0x53 -> 0x54)
        synced_cc: Optional[str] = None
        if cc_bytes is not None:
            _stage("syncing_country", f"Syncing Wi-Fi regulatory domain ({cc_bytes.decode('ascii')})...")
            link.drain()
            if sess is not None:
                req = encode_ble_frame(CMD_COUNTRY_SYNC_REQ, sess.seal_ble(CMD_COUNTRY_SYNC_REQ, cc_bytes),
                                       flags=BLE_FLAG_MD_TS)
            else:
                req = encode_ble_frame(CMD_COUNTRY_SYNC_REQ, cc_bytes, flags=BLE_FLAG_PLAIN)
            link.send_frame(req)
            cc_rsp = _recv_matching(link, lambda f: f.cmd_id == CMD_COUNTRY_SYNC_RSP, timeout=3.0)
            if cc_rsp is not None:
                pt = sess.open_ble(cc_rsp.cmd_id, cc_rsp.flags, cc_rsp.payload) if sess is not None else cc_rsp.payload
                if pt[:1] == b"\x00":
                    synced_cc = cc_bytes.decode("ascii")

        # 5. Query SoftAP Wi-Fi Credentials (0x50 -> 0x51; retry across brief hostapd restarts)
        _stage("reading_softap", "Reading robot SoftAP Wi-Fi credentials...")
        ssid = password = ""
        attempts = 5 if sess is not None else 2
        for attempt in range(attempts):
            link.drain()
            if sess is not None:
                req = encode_ble_frame(CMD_WIFI_CRED_REQ, sess.seal_ble(CMD_WIFI_CRED_REQ, b""),
                                       flags=BLE_FLAG_MD_TS)
            else:
                req = encode_ble_frame(CMD_WIFI_CRED_REQ, b"", flags=BLE_FLAG_PLAIN)
            link.send_frame(req)
            wf_rsp = _recv_matching(link, lambda f: f.cmd_id == CMD_WIFI_CRED_RSP, timeout=2.0)
            if wf_rsp is not None:
                pt = sess.open_ble(wf_rsp.cmd_id, wf_rsp.flags, wf_rsp.payload) if sess is not None else wf_rsp.payload
                ssid, password = decode_softap_payload(pt)
                break
            if attempt + 1 < attempts:
                time.sleep(0.5)
        if not ssid:
            raise BleError("SOFTAP_QUERY_FAILED", "robot did not return SoftAP credentials (0x51)")

        saved_path = ident.path or md_ts.default_identity_path()
        if robot_pub is not None:
            ident.remember_robot(
                robot_pub,
                ble_address=dev_info.address,
                ssid=ssid,
                device_name=dev_info.name,
                host=SOFTAP_DEFAULT_HOST,
            )
            saved_path = ident.save(identity_path)

        softap = SoftApCredentials(
            ssid=ssid,
            password=password,
            host=SOFTAP_DEFAULT_HOST,
            port=SOFTAP_DEFAULT_PORT,
            security_mode="md-ts" if sess is not None else "plaintext",
            country_synced=synced_cc,
        )
        _stage("paired", f"Paired with {dev_info.name} — SoftAP SSID {ssid!r}")
        return BlePairingResult(
            device=dev_info,
            softap=softap,
            identity_path=saved_path,
            client_id_hex=ident.client_id.hex(),
            robot_public_key_hex=robot_pub.hex() if robot_pub else "",
            button_held=button_held,
        )
    finally:
        link.close()


# ── Optional Host OS Wi-Fi Helper (macOS `networksetup` / Linux `nmcli`) ─────
class HostWifiManager:
    """Opt-in helper to temporarily join the robot's SoftAP (`192.168.7.1`) and restore Wi-Fi.

    Never places Wi-Fi passwords in logged messages; on Linux uses `nmcli --ask` via stdin so
    the PSK never appears in `ps` / `argv`.
    """

    def __init__(self, interface: Optional[str] = None) -> None:
        self._sys = platform.system()
        self.interface = interface or self._detect_interface()

    def _detect_interface(self) -> Optional[str]:
        if self._sys == "Darwin":
            if not shutil.which("networksetup"):
                return None
            res = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, check=False, timeout=5.0,
            )
            lines = res.stdout.splitlines()
            for idx, line in enumerate(lines):
                if "Wi-Fi" in line or "AirPort" in line:
                    for sub in lines[idx + 1:idx + 4]:
                        m = re.search(r"Device:\s*(\S+)", sub)
                        if m:
                            return m.group(1)
            return "en0"
        if self._sys == "Linux":
            if not shutil.which("nmcli"):
                return None
            res = subprocess.run(
                ["nmcli", "-t", "-f", "DEVICE,TYPE", "device"],
                capture_output=True, text=True, check=False, timeout=5.0,
            )
            for line in res.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] == "wifi":
                    return parts[0]
        return None

    def current_ssid(self) -> Optional[str]:
        if not self.interface:
            return None
        if self._sys == "Darwin" and shutil.which("networksetup"):
            res = subprocess.run(
                ["networksetup", "-getairportnetwork", self.interface],
                capture_output=True, text=True, check=False, timeout=5.0,
            )
            m = re.search(r"Current Wi-Fi Network:\s*(.+)", res.stdout)
            return m.group(1).strip() if m else None
        if self._sys == "Linux" and shutil.which("nmcli"):
            res = subprocess.run(
                ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"],
                capture_output=True, text=True, check=False, timeout=5.0,
            )
            for line in res.stdout.splitlines():
                if line.startswith("yes:"):
                    return line[4:].strip() or None
        return None

    def join(self, ssid: str, password: str = "") -> None:
        if not self.interface:
            raise BleError(
                "OS_WIFI_UNSUPPORTED",
                "automatic OS Wi-Fi switching is unavailable on this machine",
                f"manually join Wi-Fi SSID {ssid!r} and re-run without --switch-os-wifi",
            )
        if self._sys == "Darwin":
            cmd = ["networksetup", "-setairportnetwork", self.interface, ssid]
            if password:
                cmd.append(password)
            res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=25.0)
            if res.returncode != 0 or "Failed" in res.stdout or "Error" in res.stdout:
                raise BleError("OS_WIFI_JOIN_FAILED", f"macOS failed to join Wi-Fi {ssid!r}")
            return
        if self._sys == "Linux":
            if password:
                cmd = ["nmcli", "--ask", "device", "wifi", "connect", ssid, "ifname", self.interface]
                res = subprocess.run(
                    cmd, input=password + "\n", capture_output=True, text=True, check=False, timeout=30.0,
                )
            else:
                cmd = ["nmcli", "device", "wifi", "connect", ssid, "ifname", self.interface]
                res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30.0)
            if res.returncode != 0:
                raise BleError("OS_WIFI_JOIN_FAILED", f"nmcli failed to join Wi-Fi {ssid!r}")
            return
        raise BleError("OS_WIFI_UNSUPPORTED", f"OS Wi-Fi switching unsupported on {self._sys}")

    def reconnect_saved(self, ssid: str) -> bool:
        if not ssid or not self.interface:
            return False
        if self._sys == "Darwin" and shutil.which("networksetup"):
            res = subprocess.run(
                ["networksetup", "-setairportnetwork", self.interface, ssid],
                capture_output=True, text=True, check=False, timeout=20.0,
            )
            return res.returncode == 0
        if self._sys == "Linux" and shutil.which("nmcli"):
            res = subprocess.run(
                ["nmcli", "connection", "up", ssid],
                capture_output=True, text=True, check=False, timeout=20.0,
            )
            return res.returncode == 0
        return False


def _discover_lan_robot_ip(port: int = SOFTAP_DEFAULT_PORT, timeout: float = 1.5) -> str:
    """Probe local IPv4 /24 subnets with `ucp:sync` on UDP `:9007` and immediately `ucp:leav`."""
    import select
    import socket
    from .transport import ACK, LEAVE, SYNC

    local_ips: List[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            ip = probe.getsockname()[0]
            if ip and not ip.startswith("127."):
                local_ips.append(ip)
    except OSError:
        pass
    if not local_ips:
        return ""
    prefix = ".".join(local_ips[0].split(".")[:3])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for hid in range(1, 255):
            cand = f"{prefix}.{hid}"
            if cand != local_ips[0]:
                try:
                    sock.sendto(SYNC, (cand, port))
                except OSError:
                    continue
        deadline = time.monotonic() + max(0.1, timeout)
        while time.monotonic() < deadline:
            r, _, _ = select.select([sock], [], [], min(0.05, max(0.0, deadline - time.monotonic())))
            if not r:
                continue
            try:
                data, peer = sock.recvfrom(256)
            except OSError:
                break
            if data[:7] == ACK:
                try:
                    sock.sendto(LEAVE, peer)
                except OSError:
                    pass
                return peer[0]
    finally:
        sock.close()
    return ""


# ── Full Stock-Robot Onboarding (`BLE -> SoftAP -> Home Wi-Fi -> LAN`) ───────
def discover_robot_ip(port: int = SOFTAP_DEFAULT_PORT, timeout: float = 1.5) -> str:
    """Find a robot on this machine's LAN by probing UDP `:9007` with `ucp:sync`.

    Returns the robot's IPv4 address, or `""` when nothing answers. The probe
    immediately sends `ucp:leav` so the robot's single UCP slot stays free.
    """
    return _discover_lan_robot_ip(port=port, timeout=timeout)


def setup_robot_wifi(
    *,
    home_ssid: str,
    home_password: str = "",
    device: Optional[str] = None,
    country_code: Optional[str] = "US",
    switch_os_wifi: bool = False,
    softap_host: str = SOFTAP_DEFAULT_HOST,
    softap_port: int = SOFTAP_DEFAULT_PORT,
    identity_path: Optional[str] = None,
    allow_key_change: bool = False,
    sim_peripheral: Optional[SimBlePeripheral] = None,
    on_stage: Optional[Callable[[str, str], None]] = None,
    on_awaiting_button: Optional[Callable[[BleDeviceInfo], None]] = None,
) -> dict:
    """Wake/pair a stock robot over BLE, connect to its SoftAP, and commit Home Wi-Fi."""
    from .client import MondoClient

    def _stage(stage: str, detail: str = "") -> None:
        if on_stage is not None:
            on_stage(stage, detail)

    pair_res = pair_and_get_softap(
        device=device,
        country_code=country_code,
        identity_path=identity_path,
        allow_key_change=allow_key_change,
        sim_peripheral=sim_peripheral,
        on_stage=on_stage,
        on_awaiting_button=on_awaiting_button,
    )

    wifi_mgr = HostWifiManager() if switch_os_wifi else None
    previous_ssid = wifi_mgr.current_ssid() if wifi_mgr is not None else None
    joined_softap = False

    try:
        if wifi_mgr is not None and previous_ssid != pair_res.softap.ssid:
            _stage("joining_softap", f"Joining robot SoftAP {pair_res.softap.ssid!r}...")
            wifi_mgr.join(pair_res.softap.ssid, pair_res.softap.password)
            joined_softap = True
            time.sleep(1.5)

        _stage(
            "connecting_softap",
            f"Opening encrypted Zenoh session to {softap_host}:{softap_port}...",
        )
        ident = md_ts.Identity.load_or_create(identity_path)
        last_err: Optional[Exception] = None
        prov_res: Optional[dict] = None
        for attempt in range(4):
            try:
                with MondoClient(
                    host=softap_host,
                    port=softap_port,
                    identity=ident,
                    security=pair_res.softap.security_mode,
                ) as client:
                    _stage("provisioning_wifi", f"Provisioning Home Wi-Fi {home_ssid!r} on robot...")
                    prov_res = client.provision_wifi(home_ssid, home_password)
                    break
            except Exception as e:
                last_err = e
                if attempt + 1 < 4:
                    time.sleep(1.0)
        if prov_res is None:
            hint = (
                "" if switch_os_wifi
                else f"connect Wi-Fi to {pair_res.softap.ssid!r} (password: {pair_res.softap.password!r}) "
                     f"or pass --switch-os-wifi"
            )
            raise BleError(
                "SOFTAP_UNREACHABLE",
                f"could not reach robot on {softap_host}:{softap_port}: {last_err}",
                hint,
            )
    finally:
        if joined_softap and wifi_mgr is not None:
            target_restore = previous_ssid or home_ssid
            if target_restore and target_restore != pair_res.softap.ssid:
                _stage("restoring_wifi", f"Reconnecting this machine to {target_restore!r}...")
                wifi_mgr.reconnect_saved(target_restore)
                time.sleep(2.0)

    lan_ip = prov_res.get("ipv4") or ""
    if not lan_ip and sim_peripheral is None:
        _stage("discovering_lan", "Scanning LAN for robot on UDP :9007...")
        lan_ip = _discover_lan_robot_ip(port=softap_port, timeout=2.0)

    if lan_ip and pair_res.robot_public_key_hex:
        ident = md_ts.Identity.load_or_create(identity_path)
        ident.remember_robot(
            bytes.fromhex(pair_res.robot_public_key_hex),
            ble_address=pair_res.device.address,
            ssid=pair_res.softap.ssid,
            device_name=pair_res.device.name,
            host=lan_ip,
        )
        ident.save(identity_path)

    _stage("done", f"Robot online on {home_ssid!r}" + (f" ({lan_ip})" if lan_ip else ""))
    return {
        "pairing": pair_res.to_dict(),
        "provision": prov_res,
        "lan_ip": lan_ip,
        "home_ssid": home_ssid,
    }


# ── CLI (`python -m freewheel.ble`) ──────────────────────────────────────────
def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m freewheel.ble",
        description="Freewheel BLE pairing, SoftAP wake, and Home Wi-Fi setup (self-contained).",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan for nearby Beni robots over Bluetooth LE")
    p_scan.add_argument("--timeout", type=float, default=5.0, help="BLE scan duration in seconds (default: 5)")
    p_scan.add_argument("--sim", action="store_true", help="Use built-in simulated BLE robot")

    for alias in ("pair", "pair-ble", "softap"):
        p_pair = sub.add_parser(
            alias,
            help="Pair static X25519 identity over BLE (3-5 s button hold) and print SoftAP Wi-Fi credentials",
        )
        p_pair.add_argument("--device", default=None, help="BLE address or device name substring")
        p_pair.add_argument("--country", default="US", help="2-letter regulatory country code (default: US)")
        p_pair.add_argument("--identity", default=None, help="Identity JSON path (default: ~/.config/freewheel/identity.json)")
        p_pair.add_argument("--button-timeout", type=float, default=35.0, help="Seconds to wait for button hold")
        p_pair.add_argument("--allow-key-change", action="store_true", help="Accept a new robot public key (after factory reset)")
        p_pair.add_argument("--sim", action="store_true", help="Run against built-in simulated BLE robot")

    p_wifi = sub.add_parser("setup-wifi", help="Wake/pair over BLE and provision Home Wi-Fi on the robot")
    p_wifi.add_argument("--ssid", required=True, help="Home 2.4/5 GHz Wi-Fi SSID for the robot to join")
    p_wifi.add_argument("--password", default=None, help="Home Wi-Fi password (prompted if omitted unless --open)")
    p_wifi.add_argument("--open", action="store_true", help="Home Wi-Fi network has no password")
    p_wifi.add_argument("--device", default=None, help="BLE address or device name substring")
    p_wifi.add_argument("--country", default="US", help="2-letter regulatory country code (default: US)")
    p_wifi.add_argument("--switch-os-wifi", action="store_true",
                        help="Temporarily switch this computer's Wi-Fi to the robot SoftAP and back")
    p_wifi.add_argument("--softap-host", default=SOFTAP_DEFAULT_HOST, help="Robot SoftAP IP (default: 192.168.7.1)")
    p_wifi.add_argument("--softap-port", type=int, default=SOFTAP_DEFAULT_PORT, help="Robot UDP port (default: 9007)")
    p_wifi.add_argument("--identity", default=None, help="Identity JSON path")
    p_wifi.add_argument("--allow-key-change", action="store_true", help="Accept a new robot public key")

    args = ap.parse_args(argv)

    def _print_stage(stage: str, detail: str) -> None:
        if detail:
            print(f"[{stage}] {detail}", file=sys.stderr)

    try:
        if args.cmd == "scan":
            sim = SimBlePeripheral() if args.sim else None
            found = scan_ble(timeout=args.timeout, sim_peripheral=sim)
            if not found:
                print("No Beni robots found over BLE.")
                return 1
            for d in found:
                rssi = f"{d.rssi} dBm" if d.rssi is not None else "n/a"
                mode = " [PAIRING]" if d.pairing_mode else ""
                print(f"{d.address}  {d.name:<16}  RSSI {rssi}{mode}")
            return 0

        if args.cmd in ("pair", "pair-ble", "softap"):
            sim = SimBlePeripheral() if args.sim else None

            def _on_btn(dev: BleDeviceInfo) -> None:
                if sim is not None:
                    threading.Timer(0.15, sim.press_button).start()

            res = pair_and_get_softap(
                device=args.device,
                country_code=args.country,
                identity_path=args.identity,
                button_timeout=args.button_timeout,
                allow_key_change=args.allow_key_change,
                sim_peripheral=sim,
                on_stage=_print_stage,
                on_awaiting_button=_on_btn,
            )
            print(f"Identity saved: {res.identity_path}")
            print(f"Robot:          {res.device.name} ({res.device.address})")
            print(f"SoftAP SSID:    {res.softap.ssid}")
            print(f"SoftAP PSK:     {res.softap.password}")
            print(f"Robot Host:     {res.softap.host}:{res.softap.port} ({res.softap.security_mode})")
            return 0

        if args.cmd == "setup-wifi":
            if args.open:
                pw = ""
            elif args.password is not None:
                pw = args.password
            else:
                pw = getpass.getpass(f"Password for {args.ssid}: ")
            out = setup_robot_wifi(
                home_ssid=args.ssid,
                home_password=pw,
                device=args.device,
                country_code=args.country,
                switch_os_wifi=args.switch_os_wifi,
                softap_host=args.softap_host,
                softap_port=args.softap_port,
                identity_path=args.identity,
                allow_key_change=args.allow_key_change,
                on_stage=_print_stage,
            )
            print(f"Provisioned Home Wi-Fi: {out['home_ssid']}")
            if out.get("lan_ip"):
                print(f"Robot LAN IP:           {out['lan_ip']}")
            print(f"Identity saved:         {out['pairing']['identity_path']}")
            return 0
    except BleError as e:
        print(f"BLE error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
