#!/usr/bin/env python3
"""Self-test for the /cmd protobuf encoder (cd sdk && python -m tests.test_cmd_proto)."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from freewheel import cmd_proto  # noqa: E402
from freewheel.cmd_proto import build_cmd, encode_message, fields_of, CmdProtoError  # noqa: E402


# minimal generic proto3 reader for verification
def _rd_varint(b, i):
    v = s = 0
    while True:
        c = b[i]; i += 1; v |= (c & 0x7F) << s; s += 7
        if not c & 0x80:
            return v, i


def _decode(b):
    i = 0; out = []
    while i < len(b):
        key, i = _rd_varint(b, i); fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _rd_varint(b, i)
        elif wt == 2:
            ln, i = _rd_varint(b, i); v = bytes(b[i:i + ln]); i += ln
        elif wt == 5:
            v = bytes(b[i:i + 4]); i += 4
        elif wt == 1:
            v = bytes(b[i:i + 8]); i += 8
        out.append((fn, wt, v))
    return out


def test_schema_loaded():
    assert len(cmd_proto.MESSAGES) > 200
    assert cmd_proto.message_for_topic("cmd/mission/request") == "MissionRequest"
    assert cmd_proto.message_for_topic("/cmd/real_rl/control_request") == "RealRlControlRequest"


def test_envelope_structure():
    pl = build_cmd("cmd/mission/request", seq=5, version=1, missionId=3, subMode=1)
    env = _decode(pl)
    assert [(fn, wt) for fn, wt, _ in env] == [(1, 2), (2, 2)]          # header(1), data(2)
    header = next(v for fn, _, v in env if fn == 1)
    data = next(v for fn, _, v in env if fn == 2)
    assert _decode(header) == [(1, 0, 5)]                               # seqNum=5
    dd = dict((fn, v) for fn, _, v in _decode(data))
    assert dd[1] == 1 and dd[2] == 3 and dd[3] == 1                     # version/missionId/subMode


def test_float_field():
    # RealRlControlRequestData.explorationScale (tag 6) is a float32
    pl = build_cmd("cmd/real_rl/control_request", seq=0, explorationScale=0.5)
    data = next(v for fn, _, v in _decode(pl) if fn == 2)
    f = next(v for fn, wt, v in _decode(data) if fn == 6 and wt == 5)
    assert struct.unpack("<f", f)[0] == 0.5


def test_uint64_field():
    pl = build_cmd("cmd/real_rl/control_request", clientSessionId=0x1_0000_0001)
    data = next(v for fn, _, v in _decode(pl) if fn == 2)
    v = dict((fn, val) for fn, _, val in _decode(data))
    assert v[5] == 0x1_0000_0001                                       # uint64 varint


def test_fields_of():
    names = [f["name"] for f in fields_of("cmd/mission/request")]
    assert names == ["version", "missionId", "subMode", "modeParams"]


def test_unknown_field_errors():
    try:
        build_cmd("cmd/mission/request", nope=1)
        assert False, "expected CmdProtoError"
    except CmdProtoError:
        pass


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
