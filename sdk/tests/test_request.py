#!/usr/bin/env python3
"""Self-test for subscribe + request/response (cd sdk && python -m tests.test_request)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from freewheel import cmd_proto  # noqa: E402
from freewheel.cmd_proto import build_cmd, decode_cmd, response_topic  # noqa: E402
from freewheel.zenoh_pico import encode_declare_subscriber, _N_DECLARE, _FLAG_N, _FLAG_M  # noqa: E402


def test_response_topic():
    assert response_topic("cmd/common/ping_req") == "cmd/common/ping_rsp"
    assert response_topic("cmd/mission/request") == "cmd/mission/request_ack"
    assert response_topic("/cmd/pnl/mode_ctrl_req") == "cmd/pnl/mode_ctrl_rsp"
    assert response_topic("cmd/common/get_version_req") == "cmd/common/get_version_rsp"
    assert response_topic("status/real_rl/status") is None       # not a request


def test_decode_roundtrip():
    pl = build_cmd("cmd/mission/request", seq=9, missionId=4, subMode=2)
    d = decode_cmd("cmd/mission/request", pl)
    assert d["seqNum"] == 9 and d["data"]["missionId"] == 4 and d["data"]["subMode"] == 2


def test_declare_subscriber_bytes():
    b = encode_declare_subscriber(7, "cmd/common/ping_rsp")
    assert b[0] == _N_DECLARE                                     # 0x1e network DECLARE
    assert b[1] == (2 | _FLAG_N | _FLAG_M)                        # did 2 | N | M = 0x62
    assert b[2] == 7                                             # sub id
    assert b"cmd/common/ping_rsp" in b


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
