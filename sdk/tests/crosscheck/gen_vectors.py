#!/usr/bin/env python3
"""Generate cross-check test vectors from an independent reference implementation.

The reference is a third-party, Apache-2.0, pure-Python Beni client written
independently of MondoApp. It claims hardware testing on an LZ110 (firmware
V26.10.28). This script runs ITS encoders on a fixed set of inputs and freezes the
bytes into `vectors.json`, which `tests/test_crosscheck.py` then checks Freewheel
against offline (no reference dependency at test time).

`REFERENCE_MODULE` / `REFERENCE_URL` below are the module identifier and upstream
location the regenerator needs in order to import the reference at all; they are
the only places the upstream project is named. Everything else — docs, prose and
data keys — describes it on its own terms.

The official-SDK PSK vector is computed from the spec in Mondo's Beni-SDK
docs (protocol-reference.en.md §Quick start), not from the reference.

Usage (reference deps: cryptography, protobuf; httpx is pulled in by an import):
    git clone $REFERENCE_URL /path/to/reference
    python -I sdk/tests/crosscheck/gen_vectors.py /path/to/reference [out.json]

Run with -I and pass the checkout as an argument; never run this from inside
the reference tree.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import struct
import subprocess
import sys

# Provenance: the reference implementation's importable module name and upstream
# location. Required to run this regenerator; not used by the frozen vectors.
REFERENCE_MODULE = "nebi"
REFERENCE_URL = "https://github.com/lukaville/nebi"


def _load_reference(root: str):
    src = os.path.join(os.path.abspath(root), f"{REFERENCE_MODULE}-lib", "src")
    if not os.path.isdir(os.path.join(src, REFERENCE_MODULE)):
        sys.exit(f"not a {REFERENCE_MODULE} checkout: {root}")
    sys.path.insert(0, src)
    commit = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    return commit


def h(b: bytes) -> str:
    return bytes(b).hex()


# ── joystick word ────────────────────────────────────────────────────────────
# Inputs use the OFFICIAL Beni-SDK field names (protocol-reference.en.md
# "/cmd/rc/joystick" bitfield). Axes are normalized floats [-1, 1]; height and
# the small enums are raw field integers. Defaults = all fields zero/neutral.
JOY_DEFAULTS = dict(ch0=0.0, ch1=0.0, ch2=0.0, ch3=0.0, roll=0.0, height=0,
                    jump_cmd=0, flip_cmd=0, max_speed=0, nav_flag=0, ispause=0,
                    islock=0, pitch_input_is_stick=0, third_person_mode=0,
                    jump_mode=0, no_liveview=0)

JOY_CASES = [
    ("all_zero_neutral", {}),
    ("reference_default_neutral", {"height": 16, "nav_flag": 1}),
    ("locked_estop_fallback", {"ispause": 1, "islock": 1}),
    ("ch0_full_forward", {"ch0": 1.0, "max_speed": 1}),
    ("ch0_full_reverse", {"ch0": -1.0, "max_speed": 1}),
    ("ch1_full_plus", {"ch1": 1.0}),
    ("ch2_gimbal_minus", {"ch2": -1.0}),
    ("ch3_roll_extremes", {"ch3": 1.0, "roll": -1.0}),
    ("mixed_axes_tall", {"ch0": 0.3, "ch1": -0.25, "ch2": 0.75, "ch3": -0.2,
                         "roll": 0.4, "height": 31, "max_speed": 2}),
    ("jump", {"jump_cmd": 1, "max_speed": 1}),
    ("standing_long_jump", {"jump_cmd": 1, "jump_mode": 1, "max_speed": 1}),
    ("flip_front", {"flip_cmd": 1}),
    ("flip_back", {"flip_cmd": 2}),
    ("flip_left", {"flip_cmd": 3}),
    ("flip_right", {"flip_cmd": 4}),
    ("nav_obstacle_avoidance", {"nav_flag": 1}),
    ("nav_auto_jump", {"nav_flag": 2}),
    ("bit60_only", {"pitch_input_is_stick": 1}),
    ("bit61_only", {"third_person_mode": 1}),
    ("bit62_only", {"jump_mode": 1}),
    ("bit63_no_liveview", {"no_liveview": 1}),
    ("every_flag_max", {"ch0": 1.0, "ch1": -1.0, "ch2": 1.0, "ch3": -1.0,
                        "roll": 1.0, "height": 31, "jump_cmd": 1, "flip_cmd": 4,
                        "max_speed": 2, "nav_flag": 2, "ispause": 1, "islock": 1,
                        "pitch_input_is_stick": 1, "third_person_mode": 1,
                        "jump_mode": 1, "no_liveview": 1}),
    # Exact .5 rounding edges: the reference uses Python round() (half-to-even) on the
    # offset value; Freewheel mirrors the app's C round() (half away from zero).
    ("rounding_edge_ch0_0p0005", {"ch0": 0.0005}),
    ("rounding_edge_ch0_m0p0015", {"ch0": -0.0015}),
    ("rounding_edge_roll_m0p5", {"roll": -0.5}),
]


def _ref_joystick(inp: dict) -> int:
    types = importlib.import_module(REFERENCE_MODULE + ".types")
    JoystickState, PostureCmd, SpeedGear, StuntDirection = (
        types.JoystickState, types.PostureCmd, types.SpeedGear, types.StuntDirection)
    wire_gear_to_enum = {0: SpeedGear.SOFT, 1: SpeedGear.STANDARD, 2: SpeedGear.SPORT}
    st = JoystickState(
        ly=inp["ch0"], lx=inp["ch1"], rx=inp["ch2"], ry=inp["ch3"], roll=inp["roll"],
        height=inp["height"] / 31.0,
        jump_trigger=bool(inp["jump_cmd"]),
        stunt=StuntDirection(inp["flip_cmd"]),
        posture=PostureCmd(inp["max_speed"]),          # reference name for bits 54-55
        speed_gear=wire_gear_to_enum[inp["nav_flag"]],  # reference name for bits 56-57
        estop=bool(inp["ispause"]),
        stand_up_fold=bool(inp["islock"]),
        action_button=bool(inp["pitch_input_is_stick"]),
        roll_mode=bool(inp["third_person_mode"]),
        turn_around=bool(inp["jump_mode"]),
    )
    # pack_wire() clears bit 63; the reference heartbeat ORs no_liveview back in
    # (UcpEndpointSession.send_heartbeat_probe). Mirror that here.
    return st.pack_wire() | (int(inp["no_liveview"]) << 63)


def _raw_fields(w: int) -> dict:
    def f(shift, mask): return (w >> shift) & mask
    return {"ch0": f(0, 0x7FF), "ch1": f(11, 0x7FF), "ch2": f(22, 0x7FF),
            "ch3": f(33, 0x3F), "roll": f(39, 0x3F), "height": f(45, 0x1F),
            "jump_cmd": f(50, 1), "flip_cmd": f(51, 7), "max_speed": f(54, 3),
            "nav_flag": f(56, 3), "ispause": f(58, 1), "islock": f(59, 1),
            "pitch_input_is_stick": f(60, 1), "third_person_mode": f(61, 1),
            "jump_mode": f(62, 1), "no_liveview": f(63, 1)}


def joystick_vectors() -> list:
    out = []
    for name, over in JOY_CASES:
        inp = {**JOY_DEFAULTS, **over}
        w = _ref_joystick(inp)
        out.append({"name": name, "inputs": inp, "word": f"0x{w:016x}",
                    "le_bytes": h(w.to_bytes(8, "little")), "raw_fields": _raw_fields(w)})
    return out


def hold_word_vectors() -> list:
    joystick_hold_word = importlib.import_module(
        REFERENCE_MODULE + ".transport.ucp").joystick_hold_word
    cases = [
        ("driving_with_jump", {"ch0": 0.8, "ch1": -0.4, "ch2": 0.2, "ch3": 0.5, "roll": 0.3,
                               "height": 20, "jump_cmd": 1, "max_speed": 2, "nav_flag": 1}),
        ("flip_while_locked_estop", {"flip_cmd": 3, "jump_mode": 1, "ispause": 1, "islock": 1,
                                     "third_person_mode": 1, "height": 10}),
    ]
    out = []
    for name, over in cases:
        inp = {**JOY_DEFAULTS, **over}
        w = _ref_joystick(inp)
        hw = joystick_hold_word(w)
        out.append({"name": name, "inputs": inp, "word": f"0x{w:016x}",
                    "hold_word": f"0x{hw:016x}", "hold_raw_fields": _raw_fields(hw)})
    return out


def rcjoystick_protobuf_vectors() -> list:
    pb = importlib.import_module(REFERENCE_MODULE + ".proto.md.protocol.cmd.rc_joystick_pb2")
    JOYSTICK_WIRE_NEUTRAL_WORD = importlib.import_module(
        REFERENCE_MODULE + ".types").JOYSTICK_WIRE_NEUTRAL_WORD
    out = []
    for name, word in [("official_doc_example_1000", 1000),
                       ("reference_neutral_wire_word", JOYSTICK_WIRE_NEUTRAL_WORD),
                       ("all_bits_set", 0xFFFFFFFFFFFFFFFF)]:
        msg = pb.RcJoystick()
        msg.data.joystick = word
        out.append({"name": name, "joystick": f"0x{word:016x}",
                    "payload": h(msg.SerializeToString())})
    return out


# ── UCP datagrams ────────────────────────────────────────────────────────────
TS = 0x01020304


def ucp_vectors() -> list:
    codec = importlib.import_module(REFERENCE_MODULE + ".transport.ucp_codec")
    SackTrailer, UcpSegment = codec.SackTrailer, codec.UcpSegment
    JOYSTICK_WIRE_NEUTRAL_WORD = importlib.import_module(
        REFERENCE_MODULE + ".types").JOYSTICK_WIRE_NEUTRAL_WORD
    word = struct.pack("<Q", JOYSTICK_WIRE_NEUTRAL_WORD)
    open_frame = bytes([0xA4]) + (0x11223344).to_bytes(4, "big")
    vecs = [
        ("heartbeat_fresh_session",
         "ch0 unreliable + SACK (flags 0x1051), counters at session start",
         dict(channel=0, reliable=False, more_fragments=False, una=0, sn=0, ts_us=TS,
              payload=word, sack=SackTrailer(rcv_nxt=0))),
        ("heartbeat_live_counters",
         "reference mid-session: una/rcv_nxt = next expected robot sn (5), own unreliable sn=42, "
         "SACK bitmap marks robot sn 6 and 8 as received out of order",
         dict(channel=0, reliable=False, more_fragments=False, una=5, sn=42, ts_us=TS,
              payload=word, sack=SackTrailer(rcv_nxt=5, bitmap_lo=0b101))),
        ("reliable_ch3_first_open",
         "first reliable segment of a session carrying an A4 OPEN (reference starts snd_nxt at 0)",
         dict(channel=3, reliable=True, more_fragments=False, una=0, sn=0, ts_us=TS,
              payload=open_frame, sack=None)),
        ("reliable_ch3_second_open",
         "second reliable segment (sn=1) - the first one Freewheel would emit",
         dict(channel=3, reliable=True, more_fragments=False, una=0, sn=1, ts_us=TS,
              payload=open_frame, sack=None)),
    ]
    out = []
    for name, note, kw in vecs:
        seg = UcpSegment(**kw)
        sack = kw["sack"]
        out.append({
            "name": name, "note": note, "channel": kw["channel"], "reliable": kw["reliable"],
            "una": kw["una"], "sn": kw["sn"], "ts_us": kw["ts_us"], "payload": h(kw["payload"]),
            "sack": None if sack is None else {"rcv_nxt": sack.rcv_nxt, "bitmap_lo": sack.bitmap_lo,
                                               "bitmap_hi": sack.bitmap_hi},
            "datagram": h(seg.encode()),
        })
    return out


# ── Zenoh-over-UCP link frames ───────────────────────────────────────────────
def zenoh_link_vectors() -> list:
    codec = importlib.import_module(REFERENCE_MODULE + ".transport.ucp_codec")
    Z_UCP_ACK, Z_UCP_CLOSE, Z_UCP_DATA, Z_UCP_OPEN = (
        codec.Z_UCP_ACK, codec.Z_UCP_CLOSE, codec.Z_UCP_DATA, codec.Z_UCP_OPEN)
    ZenohUcpFrame = importlib.import_module(
        REFERENCE_MODULE + ".transport.zenoh_tunnel").ZenohUcpFrame
    aid = 0x11223344
    msg1 = bytes.fromhex("0d0102030405")      # opaque zenoh message bytes
    msg2 = bytes.fromhex("e1aabb")
    lp = lambda m: struct.pack("<H", len(m)) + m  # noqa: E731  zenoh TCP stream framing
    out = []
    for name, ft in [("A4_open", Z_UCP_OPEN), ("A5_ready", Z_UCP_ACK), ("A6_close", Z_UCP_CLOSE)]:
        out.append({"name": name, "frame_type": ft, "id": aid,
                    "frame": h(ZenohUcpFrame(ft, aid).encode())})
    out.append({"name": "A7_one_message", "frame_type": Z_UCP_DATA, "id": aid & 0xFFFF,
                "messages": [h(msg1)],
                "frame": h(ZenohUcpFrame(Z_UCP_DATA, aid, lp(msg1)).encode())})
    out.append({"name": "A7_two_messages", "frame_type": Z_UCP_DATA, "id": aid & 0xFFFF,
                "messages": [h(msg1), h(msg2)],
                "frame": h(ZenohUcpFrame(Z_UCP_DATA, aid, lp(msg1) + lp(msg2)).encode())})
    return out


# ── MD-TS (secure_v2) key schedule + AEAD known-answer vectors ───────────────
def _x25519_pub(priv: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _x25519(priv: bytes, pub: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


def md_ts_vectors() -> dict:
    wire = importlib.import_module(REFERENCE_MODULE + ".md_ts.wire")
    _session = importlib.import_module(REFERENCE_MODULE + ".md_ts.session")
    MdTsSession, derive_md_ts_session_keys = (
        _session.MdTsSession, _session.derive_md_ts_session_keys)
    client_priv = bytes(range(0x01, 0x21))
    robot_priv = bytes(range(0x41, 0x61))
    client_pub, robot_pub = _x25519_pub(client_priv), _x25519_pub(robot_priv)
    client_id = bytes(range(0xA0, 0xB0))
    key_version = 1
    client_nonce = bytes(range(0x10, 0x30))
    server_nonce = bytes(range(0x50, 0x70))
    channel_id = bytes.fromhex("c0c1c2c3c4c5c6c7")
    T = wire.MD_TS_TRANSPORT_ZENOH
    common = dict(transport_type=T, client_id=client_id, key_version=key_version,
                  client_static_pub=client_pub, robot_static_pub=robot_pub,
                  client_nonce=client_nonce, server_nonce=server_nonce, channel_id=channel_id)
    th, k_c2s, k_s2c = derive_md_ts_session_keys(
        local_private_key_bytes=client_priv, peer_public_key_bytes=robot_pub, **common)
    client = MdTsSession.from_handshake(role=wire.MD_TS_ROLE_CLIENT, local_private_key_bytes=client_priv,
                                        peer_public_key_bytes=robot_pub, **common)
    server = MdTsSession.from_handshake(role=wire.MD_TS_ROLE_SERVER, local_private_key_bytes=robot_priv,
                                        peer_public_key_bytes=client_pub, **common)
    ping_ke = "app/cmd/common/ping_req"
    ping_pt = bytes.fromhex("0a020801" "1212" "0a10") + bytes(range(16))  # header{seq=1}, data{ping_data}
    sealed_1 = client.seal_zenoh_payload(ping_ke, ping_pt)
    sealed_2 = client.seal_zenoh_payload(ping_ke, ping_pt)
    return {
        "source": "reference md_ts (session.py, wire.py)",
        "transport_type": T, "key_version": key_version,
        "client_static_priv": h(client_priv), "client_static_pub": h(client_pub),
        "robot_static_priv": h(robot_priv), "robot_static_pub": h(robot_pub),
        "client_id": h(client_id), "client_nonce": h(client_nonce), "server_nonce": h(server_nonce),
        "channel_id": h(channel_id),
        "shared_secret": h(_x25519(client_priv, robot_pub)),
        "transcript_preimage_prefix": h(b"MD-TS-HS\x00" + wire.MD_TS_VERSION),
        "transcript_hash": h(th),
        "hkdf_salt": h(hashlib.sha256(client_nonce + server_nonce).digest()),
        "hkdf_info_prefix": h(b"MD-TS-KEY\x00\x01\x01"),
        "key_c2s": h(k_c2s), "key_s2c": h(k_s2c),
        "hs_session_start": h(wire.build_hs_session_start(client_id, key_version, client_nonce)),
        "hs_session_challenge": h(wire.build_hs_session_challenge(client_id, key_version, server_nonce, channel_id)),
        "zenoh_hs_envelope_session_start": h(wire.encode_zenoh_hs_envelope(
            wire.build_hs_session_start(client_id, key_version, client_nonce))),
        "client_confirm_record": h(client.seal_handshake_confirm(client_id=client_id, key_version=key_version)),
        "server_confirm_record": h(server.seal_handshake_confirm(client_id=client_id, key_version=key_version)),
        "zenoh_aad_seq1": h(wire.build_zenoh_aad(wire.MD_TS_DIR_C2S, channel_id, 1, ping_ke)),
        "sealed_payload": {"keyexpr": ping_ke, "encoding": "application/protobuf",
                           "plaintext": h(ping_pt), "seq1_envelope": h(sealed_1),
                           "seq2_envelope": h(sealed_2)},
    }


# ── Official Beni-SDK LAN PSK (from Mondo's docs, not the reference) ────────
def official_psk_vector() -> dict:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    sdk_priv = bytes(range(0x21, 0x41))
    device_priv = bytes(range(0x61, 0x81))
    pair_id = bytes(range(0xD0, 0xE0))
    info = b"Beni LAN TLS 1.3 external PSK v1"
    shared = _x25519(sdk_priv, _x25519_pub(device_priv))
    psk = HKDF(algorithm=hashes.SHA256(), length=32, salt=pair_id, info=info).derive(shared)
    return {
        "source": "Mondo-Robotics/Beni-SDK docs/protocol-reference.en.md, Quick start step 2",
        "sdk_private_key": h(sdk_priv), "sdk_public_key": h(_x25519_pub(sdk_priv)),
        "device_private_key": h(device_priv), "device_public_key": h(_x25519_pub(device_priv)),
        "pair_id": h(pair_id), "hkdf_info": info.decode(), "shared_secret": h(shared), "psk": h(psk),
        "tls_identity": "Beni-SDK-v1", "cipher_suite": "TLS_AES_128_GCM_SHA256",
    }


def main(argv: list) -> None:
    if len(argv) < 2:
        sys.exit(__doc__)
    commit = _load_reference(argv[1])
    out_path = argv[2] if len(argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                          "vectors.json")
    doc = {
        "_meta": {
            "generator": "sdk/tests/crosscheck/gen_vectors.py",
            "reference": "independent Apache-2.0 community Python SDK (see gen_vectors.py)",
            "reference_commit": commit,
            "note": "Bytes come from the reference encoders (except official_sdk_psk). They are a "
                    "second opinion, not ground truth: the reference reports testing on one "
                    "LZ110 / V26.10.28.",
        },
        "joystick": joystick_vectors(),
        "joystick_hold_word": hold_word_vectors(),
        "rcjoystick_protobuf": rcjoystick_protobuf_vectors(),
        "ucp": ucp_vectors(),
        "zenoh_link": zenoh_link_vectors(),
        "md_ts": md_ts_vectors(),
        "official_sdk_psk": official_psk_vector(),
    }
    with open(out_path, "w") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    print(f"wrote {out_path} (reference {commit[:12]})")


if __name__ == "__main__":
    main(sys.argv)
