#!/usr/bin/env python3
"""Tests for BLE pairing, SoftAP wake, and `/cmd/nm/wifi_*` onboarding (self-contained).

Run: cd sdk && python3 tests/test_ble.py
"""
from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from freewheel import MondoClient, ble, md_ts  # noqa: E402
from freewheel.sitl import SimResponder as _SimResponder  # noqa: E402


def test_crc8_autosar_and_v0_framing():
    # Beni BLE CRC-8 uses AUTOSAR poly=0x2F with init=0x99, xor_out=0x00
    assert ble.crc8_autosar(b"123456789") == 0x2C
    assert ble.encode_ble_frame(ble.CMD_WIFI_CRED_REQ).hex() == "55050050f9"

    raw = ble.encode_ble_frame(ble.CMD_COUNTRY_SYNC_REQ, b"US", flags=ble.BLE_FLAG_PLAIN)
    assert raw[:4] == bytes([0x55, 7, 0x00, 0x53])
    frm = ble.decode_ble_frame(raw)
    assert frm.cmd_id == 0x53 and frm.flags == 0x00 and frm.payload == b"US"

    # Tampered CRC rejected
    bad = bytearray(raw)
    bad[-1] ^= 0x01
    try:
        ble.decode_ble_frame(bytes(bad))
    except ble.BleError as e:
        assert e.code == "BAD_CRC"
    else:
        raise AssertionError("expected BAD_CRC")


def test_ble_stream_parser_chunking_and_resync():
    f1 = ble.encode_ble_frame(0x54, b"\x00", flags=ble.BLE_FLAG_MD_TS)
    f2 = ble.encode_ble_frame(0x51, ble.encode_softap_payload("Beni-AB12", "hunter22"),
                              flags=ble.BLE_FLAG_MD_TS)
    corrupt = bytearray(ble.encode_ble_frame(0x54, b"\x99"))
    corrupt[-1] ^= 0xFF

    # Garbage prefix + valid f1 + corrupt frame (containing 0x55 SOF) + valid f2, fed 3 bytes at a time
    stream = b"\x00\xff\x13" + f1 + bytes(corrupt) + f2
    parser = ble.BleStreamParser()
    out = []
    for i in range(0, len(stream), 3):
        out.extend(parser.push(stream[i:i + 3]))
    assert len(out) == 2
    assert out[0].cmd_id == 0x54 and out[0].payload == b"\x00"
    assert out[1].cmd_id == 0x51
    assert ble.decode_softap_payload(out[1].payload) == ("Beni-AB12", "hunter22")
    assert parser.crc_errors >= 1 and parser.resyncs >= 1


def test_advertisement_matching():
    d1 = ble.match_beni_advertisement(
        address="AA:BB:CC:11:22:33",
        name="Beni-1122",
        service_uuids=[ble.BLE_SERVICE_UUID],
        manufacturer_data={0xFFFE: b"\x01\x00\x01"},
        rssi=-51,
    )
    assert d1 is not None and d1.pairing_mode is True and d1.rssi == -51

    # Non-Beni BLE device ignored
    assert ble.match_beni_advertisement(
        address="11:22:33:44:55:66",
        name="AirPods Pro",
        service_uuids=["0000180f-0000-1000-8000-00805f9b34fb"],
    ) is None


def test_md_ts_ble_aad_hs_and_records():
    cid = bytes.fromhex("00112233445566778899aabbccddeeff")
    cpub = md_ts.x25519_public(b"\x02" * 32)
    rpub = md_ts.x25519_public(b"\x03" * 32)

    h1 = md_ts.parse_hs(md_ts.build_client_hello(cid, 1, cpub))
    assert h1.msg_type == md_ts.HS_CLIENT_HELLO and h1.public_key == cpub
    h2 = md_ts.parse_hs(md_ts.build_server_hello(cid, 1, rpub))
    assert h2.msg_type == md_ts.HS_SERVER_HELLO and h2.public_key == rpub
    h3 = md_ts.parse_hs(md_ts.build_pending_button(cid, 1, 0x01))
    assert h3.msg_type == md_ts.HS_PENDING_BUTTON and h3.pending_status == 0x01

    aad = md_ts.ble_aad(md_ts.DIR_C2S, b"\x05" * 8, 1, bytes([0x55, 39, 0x04, 0x53]))
    assert len(aad) == 35 and aad[:15] == b"MD-TS-AAD\x00\x01\x01\x01\x00\x01"

    cn, sn, chid = b"\x04" * 32, b"\x06" * 32, b"\x07" * 8
    cs = md_ts.Session.from_handshake(
        role=md_ts.ROLE_CLIENT, transport=md_ts.TRANSPORT_BLE,
        private_key=b"\x02" * 32, peer_public_key=rpub,
        client_id=cid, key_version=1, client_pub=cpub, robot_pub=rpub,
        client_nonce=cn, server_nonce=sn, channel_id=chid,
    )
    ss = md_ts.Session.from_handshake(
        role=md_ts.ROLE_SERVER, transport=md_ts.TRANSPORT_BLE,
        private_key=b"\x03" * 32, peer_public_key=cpub,
        client_id=cid, key_version=1, client_pub=cpub, robot_pub=rpub,
        client_nonce=cn, server_nonce=sn, channel_id=chid,
    )
    c_conf = cs.seal_ble_confirm(cid, 1)
    assert len(c_conf) == 87
    ss.open_ble_confirm(c_conf, cid, 1)
    cs.open_ble_confirm(ss.seal_ble_confirm(cid, 1), cid, 1)

    rec = cs.seal_ble(0x53, b"US")
    assert ss.open_ble(0x53, 0x04, rec) == b"US"
    # Wrong cmd_id in BLE header fails 35-byte AAD verification
    try:
        ss.open_ble(0x50, 0x04, cs.seal_ble(0x53, b"US"))
    except md_ts.MdTsError as e:
        assert e.code == "BAD_TAG"
    else:
        raise AssertionError("expected BAD_TAG on BLE header cmd_id tamper")


def test_ble_button_hold_pairing_reconnect_and_tofu_pinning():
    with tempfile.TemporaryDirectory() as tmp:
        id_path = os.path.join(tmp, "identity.json")
        sim_ble = ble.SimBlePeripheral(
            address="AA:BB:CC:DD:EE:99",
            name="Beni-TEST99",
            ssid="Beni-TEST99",
            password="softap-secret-99",
            mtu_payload=20,   # force realistic 20B BLE 4.0 ATT notification chunking
        )
        stages = []

        # 1. First pairing requires 3-5 s button hold -> auto-creates identity.json (0600)
        res1 = ble.pair_and_get_softap(
            identity_path=id_path,
            country_code="US",
            sim_peripheral=sim_ble,
            on_stage=lambda s, _d: stages.append(s),
            on_awaiting_button=lambda _dev: threading.Timer(0.1, sim_ble.press_button).start(),
        )
        assert "awaiting_button" in stages and res1.button_held is True
        assert res1.softap.ssid == "Beni-TEST99" and res1.softap.password == "softap-secret-99"
        assert res1.softap.country_synced == "US"
        mode = stat.S_IMODE(os.stat(id_path).st_mode)
        assert mode == 0o600
        ident = md_ts.Identity.load(id_path)
        assert ident.robot_public_key == sim_ble.public_key
        assert ident.lookup_robot_key(ble_address="AA:BB:CC:DD:EE:99") == sim_ble.public_key

        # 2. Second connection with paired identity skips button hold
        stages2 = []
        res2 = ble.pair_and_get_softap(
            identity_path=id_path,
            country_code="JP",
            sim_peripheral=sim_ble,
            on_stage=lambda s, _d: stages2.append(s),
        )
        assert "awaiting_button" not in stages2 and res2.button_held is False
        assert sim_ble.country_code == "JP"

        # 3. TOFU key-change guard rejects impostor robot at same BLE address unless allow_key_change=True
        impostor = ble.SimBlePeripheral(
            address="AA:BB:CC:DD:EE:99",
            name="Beni-TEST99",
            authorized={ident.client_id: ident.public_key},
        )
        try:
            ble.pair_and_get_softap(identity_path=id_path, sim_peripheral=impostor)
        except ble.BleError as e:
            assert e.code == "ROBOT_KEY_CHANGED"
        else:
            raise AssertionError("expected ROBOT_KEY_CHANGED")

        res3 = ble.pair_and_get_softap(
            identity_path=id_path, sim_peripheral=impostor, allow_key_change=True,
        )
        assert res3.robot_public_key_hex == impostor.public_key.hex()

        # 4. Busy robot (status 0x03) surfaces BLE_AUTH_BUSY immediately
        busy_ble = ble.SimBlePeripheral(busy=True)
        try:
            ble.pair_and_get_softap(identity_path=id_path, sim_peripheral=busy_ble)
        except ble.BleError as e:
            assert e.code == "BLE_AUTH_BUSY"
        else:
            raise AssertionError("expected BLE_AUTH_BUSY")


def test_e2e_ble_pair_then_md_ts_zenoh_wifi_provisioning():
    with tempfile.TemporaryDirectory() as tmp:
        id_path = os.path.join(tmp, "identity.json")
        sim_ble = ble.SimBlePeripheral()
        pair = ble.pair_and_get_softap(
            identity_path=id_path,
            sim_peripheral=sim_ble,
            on_awaiting_button=lambda _dev: threading.Timer(0.05, sim_ble.press_button).start(),
        )
        ident = md_ts.Identity.load(pair.identity_path)

        # Spin up a Zenoh UCP responder requiring MD-TS with the exact keys paired over BLE
        sec = md_ts.Responder(sim_ble.private_key, sim_ble.authorized)
        sim = _SimResponder("127.0.0.1", 0, md_ts_responder=sec, enable_video=False)
        sim.start()
        port = sim._sock.getsockname()[1]  # noqa: SLF001
        try:
            with MondoClient(host="127.0.0.1", port=port, identity=ident, security="md-ts") as client:
                aps = client.scan_wifi()
                assert client.security_state == "md-ts"
                assert len(aps) == 2 and aps[0]["ssid"] == "HomeNet-5G"

                # Wrong password -> robot reports WRONG_KEY
                try:
                    client.provision_wifi("HomeNet-5G", "wrong-pass", timeout=5.0)
                except RuntimeError as e:
                    assert "WRONG_KEY" in str(e)
                else:
                    raise AssertionError("expected WRONG_KEY failure")

                # Valid password -> 3-stage commit succeeds and returns robot LAN IPv4
                ok = client.provision_wifi("HomeNet-5G", "correct-horse", timeout=5.0)
                assert ok["ok"] is True and ok["state"] == "succeeded"
                assert ok["ipv4"] == "192.168.1.42"

                client.switch_wifi_to_ap()
                time.sleep(0.1)
                assert sim._wifi_mode == "ap"  # noqa: SLF001
        finally:
            sim.stop()


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
