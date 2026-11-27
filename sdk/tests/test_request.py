#!/usr/bin/env python3
"""Self-test for subscribe + request/response (cd sdk && python -m tests.test_request)."""
import os
import sys
import time

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


def test_end_to_end_request():
    """request() declares a subscriber, publishes the _req, and gets the _rsp Push
    correlated by seqNum, decoded — against the SITL robot peer."""
    from freewheel.sitl import SimResponder as _SimResponder
    from freewheel import MondoClient
    sim = _SimResponder("127.0.0.1", 9011)
    sim.start()
    time.sleep(0.2)
    c = MondoClient(host="127.0.0.1", port=9011, log=lambda m: None)
    c.connect()
    time.sleep(0.3)
    try:
        r1 = c.request("cmd/common/ping_req", timeout=2.0)
        r2 = c.request("cmd/mission/request", timeout=2.0, missionId=5)
        assert r1 is not None and r1["seqNum"] == 1, "ping response missing/mismatched"
        assert r2 is not None and r2["seqNum"] == 2, "mission response missing/mismatched"
        # a second ping gets a fresh seqNum and still correlates
        r3 = c.request("cmd/common/ping_req", timeout=2.0)
        assert r3 is not None and r3["seqNum"] == 3
    finally:
        c.close()
        sim.stop()


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
