#!/usr/bin/env python3
"""Self-test for the zenoh-pico batch decoder (cd sdk && python -m tests.test_zenoh_pico)."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from freewheel.zenoh_pico import (  # noqa: E402
    ZenohPicoDecoder, Put, Del, DeclareKeyExpr, Encoding, Timestamp,
    decode_batch, encode_batch, encode_put, encode_del, encode_frame,
    enc_zint, enc_string, _FLAG_N, _FLAG_M, _N_PUSH, _N_DECLARE, _T_FRAME, _B_PUT, _PUT_T,
)


def test_zint_roundtrip():
    from freewheel.zenoh_pico import _Reader
    for v in (0, 1, 127, 128, 300, 16384, 2**32 - 1, 2**53):
        r = _Reader(enc_zint(v))
        assert r.zint() == v, v


def test_put_roundtrip():
    batch = encode_batch([("state/battery", b"\x5a", 0),
                          ("sensors/temp", b"21.5", 17)])
    msgs = decode_batch(batch)
    assert len(msgs) == 2
    assert isinstance(msgs[0], Put) and msgs[0].keyexpr == "state/battery"
    assert msgs[0].payload == b"\x5a"
    assert msgs[1].keyexpr == "sensors/temp" and msgs[1].payload == b"21.5"
    assert msgs[1].value() == "21.5"             # encoding 17 → text


def test_float_payload_value():
    val = struct.pack("<fff", 1.0, 2.0, 3.0)
    (put,) = decode_batch(encode_batch([("state/pose", val)]))
    assert put.payload == val
    assert put.value() == val.hex()              # binary → hex view


def test_encoding_with_schema():
    # PUT with encoding id=19 + schema "custom" (combined = (19<<1)|1)
    from freewheel.zenoh_pico import _FLAG_N as N
    we = enc_zint(0) + enc_string("x/y")
    body = bytes([_B_PUT | 0x40]) + enc_zint((19 << 1) | 1) + enc_string("custom") + \
        enc_zint(3) + b"abc"
    frame = bytes([_T_FRAME]) + enc_zint(0) + bytes([_N_PUSH | N]) + we + body
    (put,) = decode_batch(frame)
    assert put.encoding.id == 19 and put.encoding.schema == b"custom"
    assert put.payload == b"abc"


def test_timestamp():
    we = enc_zint(0) + enc_string("k")
    tsid = b"\xaa\xbb"
    body = bytes([_B_PUT | _PUT_T]) + enc_zint(123456789) + bytes([len(tsid)]) + tsid + \
        enc_zint(2) + b"hi"
    frame = bytes([_T_FRAME]) + enc_zint(0) + bytes([_N_PUSH | _FLAG_N]) + we + body
    (put,) = decode_batch(frame)
    assert put.timestamp.time == 123456789 and put.timestamp.id == tsid
    assert put.payload == b"hi"


def test_declare_resolves_scoped_keyexpr():
    dec = ZenohPicoDecoder()
    # DeclareKeyExpr rid=7 → "robot/state"  (declaration header 0x20 = DECL_KEXPR + N)
    decl = bytes([_N_DECLARE]) + bytes([0x00 | 0x20]) + enc_zint(7) + \
        enc_zint(0) + enc_string("robot/state")
    # PUSH scope=7 (no suffix) → resolves to "robot/state"
    push = bytes([_N_PUSH]) + enc_zint(7) + bytes([_B_PUT]) + enc_zint(1) + b"\x01"
    frame = bytes([_T_FRAME]) + enc_zint(0) + decl + push
    msgs = dec.decode_batch(frame)
    assert isinstance(msgs[0], DeclareKeyExpr) and msgs[0].rid == 7
    assert dec.resources[7] == "robot/state"
    assert isinstance(msgs[1], Put) and msgs[1].keyexpr == "robot/state"
    assert msgs[1].payload == b"\x01"


def test_del_message():
    we = enc_zint(0) + enc_string("gone/topic")
    frame = bytes([_T_FRAME]) + enc_zint(0) + bytes([_N_PUSH | _FLAG_N]) + we + bytes([2])  # DEL
    (d,) = decode_batch(frame)
    assert isinstance(d, Del) and d.keyexpr == "gone/topic"


def test_encode_headers_match_app():
    # push header = PUSH|M|N, frame header = FRAME|reliable — exact to _z_push_encode
    net = encode_put("cmd/x", b"\x01", encoding=18)
    assert net[0] == (_N_PUSH | _FLAG_M | _FLAG_N) == 0x7D
    frame = encode_frame(7, net, reliable=True)
    assert frame[0] == 0x25                       # FRAME 0x05 | reliable 0x20
    assert frame[1] == 7                           # SN
    # encoding zint = (18<<1)|0 = 0x24 appears after the put body header (0x41 = PUT|E)
    assert b"\x41\x24" in frame


def test_encode_del_roundtrip():
    frame = encode_frame(0, encode_del("gone/x"), reliable=False)
    assert frame[0] == 0x05                        # not reliable
    (m,) = decode_batch(frame)
    assert isinstance(m, Del) and m.keyexpr == "gone/x"


def test_publisher_roundtrip():
    """ZenohPublisher output (A4 + A7-wrapped frames) decodes back to the Puts."""
    from freewheel.zenoh import ZenohPublisher, iter_frames, FrameType
    sent = []
    pub = ZenohPublisher(send=sent.append, epoch=0x42)
    pub.put("cmd/mission/start", b"go")
    pub.put("cmd/speaker/play", b'{"id":3}', encoding=18)
    # first frame is the A4 CONNECT; the rest are A7 DATA carrying zenoh batches
    types = [list(iter_frames(p))[0].type for p in sent]
    assert types[0] is FrameType.CONNECT and types[1:] == [FrameType.DATA, FrameType.DATA]
    dec = ZenohPicoDecoder()
    puts = []
    for p in sent[1:]:
        batch = list(iter_frames(p))[0].payload     # unwrap A7 → zenoh-pico batch
        puts += [m for m in dec.decode_batch(batch) if isinstance(m, Put)]
    assert [m.keyexpr for m in puts] == ["cmd/mission/start", "cmd/speaker/play"]
    assert puts[0].payload == b"go" and puts[1].encoding.id == 18


def test_malformed_returns_partial():
    good = encode_batch([("a/b", b"x")])
    msgs = decode_batch(good + b"\x05\xff\xff")   # valid put then garbage frame
    assert any(isinstance(m, Put) and m.keyexpr == "a/b" for m in msgs)


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
