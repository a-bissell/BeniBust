#!/usr/bin/env python3
"""Cross-check Freewheel against frozen community vectors (python -m tests.test_crosscheck).

`tests/crosscheck/vectors.json` was produced by `tests/crosscheck/gen_vectors.py`
from a community SDK's encoders. That project is not needed to run this. Agreement is asserted where the two implementations should agree.
Where they are known to differ, the test pins the exact difference, so a change
on either side gets noticed. UCP counters and SACK were aligned with the community
notes, so those vectors are now asserted byte-identical. See
native-analysis/community-crosscheck.md.

The MD-TS and official-SDK PSK sections have no Freewheel implementation yet.
Here they are recomputed independently from the documented key schedule:
stdlib SHA-256/HKDF, plus `cryptography` for X25519/AES-GCM when it's installed.
"""
import hashlib
import hmac
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from freewheel import transport, zenoh                  # noqa: E402
from freewheel.control import pack_control, unpack_control  # noqa: E402

_VEC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crosscheck", "vectors.json")
with open(_VEC_PATH) as _fh:
    V = json.load(_fh)

try:  # optional: only needed for X25519 / AES-GCM checks
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

B = bytes.fromhex


def _fw_pack(i: dict) -> bytes:
    """Official-SDK field names -> Freewheel pack_control (bit 60 is still `min_turn_mode` here)."""
    return pack_control(
        ch0=i["ch0"], ch1=i["ch1"], ch2=i["ch2"], ch3=i["ch3"], roll=i["roll"],
        height=i["height"], jump_cmd=bool(i["jump_cmd"]), flip_cmd=i["flip_cmd"],
        max_speed=i["max_speed"], nav_flag=i["nav_flag"], ispause=bool(i["ispause"]),
        islock=bool(i["islock"]), min_turn_mode=bool(i["pitch_input_is_stick"]),
        third_person_mode=bool(i["third_person_mode"]), jump_mode=bool(i["jump_mode"]),
        video_enabled=not i["no_liveview"])


# Half-way inputs: the community SDK applies Python round() (half-to-even) before
# adding the centre; Freewheel mirrors the app's C round() (half away from zero)
# after. Each entry: field -> (freewheel raw, community raw).
ROUNDING_EDGES = {
    "rounding_edge_ch0_0p0005": {"ch0": (1001, 1000)},
    "rounding_edge_ch0_m0p0015": {"ch0": (999, 998)},
    "rounding_edge_roll_m0p5": {"roll": (16, 15)},
}


# ── joystick word ────────────────────────────────────────────────────────────
def test_joystick_words_match_reference_vectors():
    for v in V["joystick"]:
        fw = _fw_pack(v["inputs"])
        if v["name"] in ROUNDING_EDGES:
            continue
        assert fw.hex() == v["le_bytes"], (v["name"], fw.hex(), v["le_bytes"])


def test_joystick_rounding_edges_differ_by_one_lsb_only():
    by_name = {v["name"]: v for v in V["joystick"]}
    for name, fields in ROUNDING_EDGES.items():
        v = by_name[name]
        fw_raw = unpack_control(_fw_pack(v["inputs"]))
        ref_raw = v["raw_fields"]
        for field, (fw_val, ref_val) in fields.items():
            key = {"ch0": "channel0"}.get(field, field)
            assert fw_raw[key] == fw_val and ref_raw[field] == ref_val, (name, field)
        # Every other field identical.
        for k, val in ref_raw.items():
            if k in fields:
                continue
            fk = {"ch0": "channel0", "ch1": "channel1", "ch2": "channel2", "ch3": "channel3",
                  "pitch_input_is_stick": "min_turn_mode"}.get(k, k)
            assert fw_raw[fk] == val, (name, k)


def test_joystick_known_app_bytes():
    # control-packet.md worked examples line up with the reference-generated words.
    by_name = {v["name"]: v for v in V["joystick"]}
    assert by_name["locked_estop_fallback"]["le_bytes"] == "e8431ffabe0f000c"
    assert by_name["ch1_full_plus"]["le_bytes"] == "e8833efabe0f0000"
    # The reference "neutral" = app's resting height 16 + bits 56-57 = 1 (official:
    # nav_flag=1, obstacle avoidance).
    assert by_name["reference_default_neutral"]["word"] == "0x01020fbefa1f43e8"
    assert by_name["reference_default_neutral"]["raw_fields"]["nav_flag"] == 1


def test_joystick_unpack_roundtrip_on_reference_words():
    for v in V["joystick"]:
        fw = unpack_control(B(v["le_bytes"]))
        r = v["raw_fields"]
        assert (fw["channel0"], fw["channel1"], fw["channel2"], fw["channel3"]) == \
               (r["ch0"], r["ch1"], r["ch2"], r["ch3"]), v["name"]
        assert fw["min_turn_mode"] == r["pitch_input_is_stick"], v["name"]
        assert fw["no_liveview"] == r["no_liveview"], v["name"]


def test_hold_word_spec():
    # The reference transport dead-man (not implemented in Freewheel yet): after
    # 0.25 s without a fresh command, sticks -> neutral, one-shot triggers cleared,
    # level/latched bits kept. NOTE the reference also clears bits 54-55 (official
    # max_speed / speed gear) because it treats them as a posture trigger.
    for v in V["joystick_hold_word"]:
        hw = unpack_control(int(v["hold_word"], 16).to_bytes(8, "little"))
        i = v["inputs"]
        assert (hw["channel0"], hw["channel1"], hw["channel2"], hw["channel3"]) == (1000, 1000, 1000, 31)
        assert hw["jump_cmd"] == hw["flip_cmd"] == hw["jump_mode"] == 0
        assert hw["max_speed"] == 0
        assert hw["islock"] == i["islock"] and hw["ispause"] == i["ispause"]
        assert hw["nav_flag"] == i["nav_flag"] and hw["height"] == i["height"]
        assert hw["third_person_mode"] == i["third_person_mode"]
        assert hw["roll"] == v["hold_raw_fields"]["roll"]  # roll is a level, kept


def _pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def test_rcjoystick_protobuf_envelope():
    # Official SDK: RcJoystick = data(tag 2){joystick(tag 1) u64}, header omitted.
    for v in V["rcjoystick_protobuf"]:
        inner = b"\x08" + _pb_varint(int(v["joystick"], 16))
        assert (b"\x12" + _pb_varint(len(inner)) + inner).hex() == v["payload"], v["name"]
    assert V["rcjoystick_protobuf"][0]["payload"] == "120308e807"  # doc example, verbatim


# ── UCP datagrams ────────────────────────────────────────────────────────────
class _Sock:
    def __init__(self):
        self.out = []

    def send(self, b):
        self.out.append(bytes(b))


def _fw_datagram(v: dict) -> bytes:
    """Freewheel's datagram for vector `v`, with its ARQ state set to the vector's counters."""
    saved = transport._now_us
    transport._now_us = lambda: v["ts_us"]
    try:
        u = transport.UcpTransport("192.0.2.1")
        u._sock = _Sock()
        u.rcv_nxt = v["una"]
        if v["reliable"]:
            u.snd_nxt = v["sn"]
        else:
            u.unrel_sn = v["sn"]
        if v["sack"]:                           # mark the bitmap's sns as received out of order
            rn, lo, hi = v["sack"]["rcv_nxt"], v["sack"]["bitmap_lo"], v["sack"]["bitmap_hi"]
            for d in range(1, 65):
                if (d <= 32 and lo >> (d - 1) & 1) or (d > 32 and hi >> (d - 33) & 1):
                    u._rx_ooo[(rn + d) & 0xFFFF] = {}
        payload = B(v["payload"])
        if v["reliable"]:
            u.send(v["channel"], payload, reliable=True)
        else:
            u.send_heartbeat(payload)
        return u._sock.out[0]
    finally:
        transport._now_us = saved


def _hdr(d: bytes):
    return transport.HEADER.unpack_from(d, 0)  # flags, una, sn, len, ts


def test_ucp_datagrams_match_reference_vectors():
    # Fresh-session heartbeat, mid-session heartbeat (una = next expected, own
    # unreliable sn, SACK bitmap), and the first two reliable ch3 segments
    # (first reliable sn is 0): all byte-identical to the reference vectors.
    for v in V["ucp"]:
        assert _fw_datagram(v).hex() == v["datagram"], v["name"]
    hb = next(x for x in V["ucp"] if x["name"] == "heartbeat_fresh_session")
    assert _hdr(B(hb["datagram"]))[0] == 0x1051
    rel = next(x for x in V["ucp"] if x["name"] == "reliable_ch3_first_open")
    assert _hdr(B(rel["datagram"]))[0] == 0x0D51 and _hdr(B(rel["datagram"]))[2] == 0


def test_ucp_fresh_transport_counters_start_at_zero():
    u = transport.UcpTransport("192.0.2.1")
    u._sock = _Sock()
    u.send(transport.CH_ZENOH, b"\xa4\x11\x22\x33\x44", reliable=True)
    u.send_heartbeat(b"\x00" * 8)
    u.send_heartbeat(b"\x00" * 8)
    rel, hb1, hb2 = (_hdr(d) for d in u._sock.out)
    assert rel[2] == 0 and u.snd_nxt == 1 and u.unacked == 1
    assert (hb1[2], hb2[2]) == (0, 1)


# ── Zenoh-over-UCP link frames ───────────────────────────────────────────────
def test_zenoh_control_frames_identical():
    enc = {"A4_open": zenoh.encode_connect, "A5_ready": zenoh.encode_ready,
           "A6_close": lambda e: zenoh.encode_control(zenoh.FrameType.CLOSE, e)}
    for v in V["zenoh_link"]:
        if v["name"] in enc:
            assert enc[v["name"]](v["id"]).hex() == v["frame"], v["name"]


def test_zenoh_a7_single_message_identical():
    # Freewheel reads A7 as tag+id+len(LE)+batch; the reference reads
    # tag+id+[u16 LE len][msg] stream.
    # Same bytes for one message per frame.
    v = next(x for x in V["zenoh_link"] if x["name"] == "A7_one_message")
    assert zenoh.encode_data(v["id"], B(v["messages"][0])).hex() == v["frame"]
    frames = list(zenoh.iter_frames(B(v["frame"])))
    assert len(frames) == 1 and frames[0].payload.hex() == v["messages"][0]


def test_zenoh_a7_two_messages_diverge():
    # The reference may pack several length-prefixed messages into one A7. Freewheel's
    # decoder takes the first length as the whole frame, then fails on the next
    # length prefix as if it were a tag. Which model the robot uses is open.
    v = next(x for x in V["zenoh_link"] if x["name"] == "A7_two_messages")
    try:
        list(zenoh.iter_frames(B(v["frame"])))
    except zenoh.ZenohError:
        return
    raise AssertionError("Freewheel now decodes multi-message A7; update the cross-check note")


# ── MD-TS (secure_v2) key schedule: independent recomputation ────────────────
def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def test_md_ts_transcript_and_keys():
    m = V["md_ts"]
    pre = (b"MD-TS-HS\x00" + b"\x01\x01" + bytes([m["transport_type"]]) + B(m["client_id"])
           + struct.pack(">I", m["key_version"]) + B(m["client_static_pub"]) + B(m["robot_static_pub"])
           + B(m["client_nonce"]) + B(m["server_nonce"]) + B(m["channel_id"]))
    assert len(pre) == 168
    th = hashlib.sha256(pre).digest()
    assert th.hex() == m["transcript_hash"]
    salt = hashlib.sha256(B(m["client_nonce"]) + B(m["server_nonce"])).digest()
    assert salt.hex() == m["hkdf_salt"]
    for d, key in ((0, "key_c2s"), (1, "key_s2c")):
        info = b"MD-TS-KEY\x00\x01\x01" + bytes([m["transport_type"], d]) + th
        assert _hkdf_sha256(B(m["shared_secret"]), salt, info).hex() == m[key], key


def test_md_ts_handshake_messages():
    m = V["md_ts"]
    hdr = lambda t: b"\x01\x01" + bytes([t]) + B(m["client_id"]) + struct.pack(">I", m["key_version"])  # noqa: E731
    start = hdr(4) + B(m["client_nonce"])
    assert start.hex() == m["hs_session_start"] and len(start) == 55
    assert (hdr(5) + B(m["server_nonce"]) + B(m["channel_id"])).hex() == m["hs_session_challenge"]
    assert (b"\x2a" + _pb_varint(len(start)) + start).hex() == m["zenoh_hs_envelope_session_start"]


def _zenoh_aad(direction: int, channel_id: bytes, seq: int, keyexpr: str,
               encoding: str = "application/protobuf") -> bytes:
    ke, enc = keyexpr.lstrip("/").encode(), encoding.encode()
    return (b"MD-TS-AAD\x00\x01\x01\x02" + bytes([direction]) + b"\x01" + channel_id
            + struct.pack(">Q", seq) + struct.pack(">H", len(ke)) + ke + struct.pack(">H", len(enc)) + enc)


def test_md_ts_aead_records():
    m = V["md_ts"]
    ch = B(m["channel_id"])
    assert _zenoh_aad(0, ch, 1, m["sealed_payload"]["keyexpr"]).hex() == m["zenoh_aad_seq1"]
    if not HAVE_CRYPTO:
        print("  (skip AES-GCM/X25519: cryptography not installed)")
        return
    priv = X25519PrivateKey.from_private_bytes(B(m["client_static_priv"]))
    assert priv.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw).hex() == m["client_static_pub"]
    shared = priv.exchange(X25519PublicKey.from_public_bytes(B(m["robot_static_pub"])))
    assert shared.hex() == m["shared_secret"]

    iv = lambda seq: b"\x00" * 8 + struct.pack(">I", seq)  # noqa: E731
    hdr = lambda t: b"\x01\x01" + bytes([t]) + B(m["client_id"]) + struct.pack(">I", m["key_version"])  # noqa: E731
    # Confirm records: channel_id || u64 BE seq(0) || AES-256-GCM(ct||tag).
    for rec_key, key, d, t, ke in (("client_confirm_record", "key_c2s", 0, 6, "app/security/session"),
                                   ("server_confirm_record", "key_s2c", 1, 7, "device/security/session")):
        rec = B(m[rec_key])
        assert rec[:8] == ch and struct.unpack(">Q", rec[8:16])[0] == 0 and len(rec) == 87
        pt = AESGCM(B(m[key])).decrypt(iv(0), rec[16:], _zenoh_aad(d, ch, 0, ke))
        assert pt == hdr(t) + B(m["transcript_hash"]), rec_key
    # Encrypted topic payload envelope: 18 01 22 <len> record.
    sp = m["sealed_payload"]
    for seq, k in ((1, "seq1_envelope"), (2, "seq2_envelope")):
        env = B(sp[k])
        assert env[:3] == b"\x18\x01\x22"
        n, i = 0, 3
        while True:  # length varint
            n |= (env[i] & 0x7F) << (7 * (i - 3))
            i += 1
            if not env[i - 1] & 0x80:
                break
        rec = env[i:]
        assert len(rec) == n
        assert rec[:8] == ch and struct.unpack(">Q", rec[8:16])[0] == seq
        pt = AESGCM(B(m["key_c2s"])).decrypt(iv(seq), rec[16:], _zenoh_aad(0, ch, seq, sp["keyexpr"]))
        assert pt.hex() == sp["plaintext"]


# ── Official Beni-SDK LAN PSK (from Mondo's docs) ────────────────────────────
def test_official_sdk_psk():
    p = V["official_sdk_psk"]
    psk = _hkdf_sha256(B(p["shared_secret"]), B(p["pair_id"]), p["hkdf_info"].encode())
    assert psk.hex() == p["psk"]
    if not HAVE_CRYPTO:
        return
    # Both sides derive the same shared secret.
    sdk = X25519PrivateKey.from_private_bytes(B(p["sdk_private_key"]))
    dev = X25519PrivateKey.from_private_bytes(B(p["device_private_key"]))
    s1 = sdk.exchange(X25519PublicKey.from_public_bytes(B(p["device_public_key"])))
    s2 = dev.exchange(X25519PublicKey.from_public_bytes(B(p["sdk_public_key"])))
    assert s1 == s2 and s1.hex() == p["shared_secret"]


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
