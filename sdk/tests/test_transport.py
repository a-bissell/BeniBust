#!/usr/bin/env python3
"""UCP ARQ behaviour (python -m tests.test_transport).

Counter/SACK semantics follow the community cross-check
(native-analysis/community-crosscheck.md §2); byte-level parity is in test_crosscheck.py. This file checks the behaviour:
in-order delivery, out-of-order buffering + SACK, duplicates, fragmentation,
retransmit/ack, immediate ack, and the 8-byte ch0 guard."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from freewheel import transport as t                     # noqa: E402
from freewheel.transport import encode_segment, decode_segments  # noqa: E402


class _Sock:
    def __init__(self):
        self.out = []

    def send(self, b):
        self.out.append(bytes(b))


def _mk():
    got = []
    u = t.UcpTransport("192.0.2.1", on_message=lambda ch, p: got.append((ch, p)))
    u._sock = _Sock()
    return u, got


def _rel(sn, payload, ch=t.CH_ZENOH, una=0, more=False):
    return encode_segment(ch, payload, reliable=True, more=more, una=una, sn=sn, ts=0)


def test_in_order_delivery_and_immediate_ack():
    u, got = _mk()
    u.send_heartbeat(b"\x01" * 8)                       # gives send_ack a payload
    u._sock.out.clear()
    u.handle_datagram(_rel(0, b"\xa7first"))
    assert got == [(3, b"\xa7first")] and u.rcv_nxt == 1
    ack = decode_segments(u._sock.out[-1])[0]
    assert ack["channel"] == 0 and not ack["reliable"] and ack["una"] == 1
    assert ack["sack"] == (1, 0, 0) and ack["payload"] == b"\x01" * 8


def test_out_of_order_buffered_sacked_then_drained():
    u, got = _mk()
    u.send_heartbeat(b"\x00" * 8)
    u.handle_datagram(_rel(1, b"\xa7b"))
    u.handle_datagram(_rel(3, b"\xa7d"))
    assert got == [] and u.rcv_nxt == 0
    sack = decode_segments(u._sock.out[-1])[0]["sack"]
    assert sack == (0, 0b101, 0)                        # sn 1 (d=1) and 3 (d=3)
    u.handle_datagram(_rel(0, b"\xa7a"))
    assert [p for _, p in got] == [b"\xa7a", b"\xa7b"] and u.rcv_nxt == 2
    u.handle_datagram(_rel(2, b"\xa7c"))
    assert [p for _, p in got] == [b"\xa7a", b"\xa7b", b"\xa7c", b"\xa7d"] and u.rcv_nxt == 4


def test_duplicate_not_redelivered_but_reacked():
    u, got = _mk()
    u.send_heartbeat(b"\x00" * 8)
    u.handle_datagram(_rel(0, b"\xa7x"))
    n = len(u._sock.out)
    u.handle_datagram(_rel(0, b"\xa7x"))
    assert got == [(3, b"\xa7x")] and len(u._sock.out) == n + 1


def test_fragment_reassembly():
    u, got = _mk()
    u.handle_datagram(_rel(0, b"\xa7AB", more=True))
    u.handle_datagram(_rel(1, b"CD", more=True))
    assert got == []
    u.handle_datagram(_rel(2, b"EF"))
    assert got == [(3, b"\xa7ABCDEF")]


def test_tx_fragmentation_and_ack_clears_window():
    u, _ = _mk()
    big = b"\xa7" + bytes(range(256)) * 12               # 3073 bytes → 3 fragments
    u.send(t.CH_ZENOH, big, reliable=True)
    segs = [decode_segments(d)[0] for d in u._sock.out]
    assert [s["sn"] for s in segs] == [0, 1, 2] and [s["more"] for s in segs] == [True, True, False]
    assert b"".join(s["payload"] for s in segs) == big and u.unacked == 3
    # robot acks sn 0 cumulatively and sn 2 selectively
    u.handle_datagram(encode_segment(0, b"", reliable=False, more=False, una=1, sn=0,
                                     sack=(1, 0b1, 0), ts=0))   # bit0 = rcv_nxt+1 = sn 2
    assert sorted(u._tx_window) == [1]
    u.handle_datagram(encode_segment(0, b"", reliable=False, more=False, una=3, sn=1, ts=0))
    assert u.unacked == 0


def test_retransmit_with_backoff_until_acked():
    u, _ = _mk()
    u.send(t.CH_ZENOH, b"\xa4\x00\x00\x00\x42", reliable=True)
    u._sock.out.clear()
    u.service()
    assert u._sock.out == []                            # before RTO
    u._tx_window[0][3] -= t.RTO_S + 0.01                # age it past the RTO
    u.rcv_nxt = 7                                       # retransmit carries the CURRENT una
    u.service()
    seg = decode_segments(u._sock.out[-1])[0]
    assert seg["reliable"] and seg["sn"] == 0 and seg["una"] == 7 and u._tx_window[0][4] == 1
    u.handle_datagram(encode_segment(0, b"", reliable=False, more=False, una=1, sn=0, ts=0))
    assert u.unacked == 0


def test_link_dead_after_max_retries():
    u, _ = _mk()
    u.send(t.CH_ZENOH, b"\xa4\x00\x00\x00\x42", reliable=True)
    u._tx_window[0][4] = t.MAX_RETRIES
    u.service()
    assert u.link_dead


def test_concatenated_segments_in_one_datagram():
    u, got = _mk()
    dg = _rel(0, b"\xa7one") + encode_segment(0, b"\xa7two", reliable=False, more=False,
                                             una=0, sn=0, sack=(0, 0, 0), ts=0)
    u.handle_datagram(dg)
    assert got == [(3, b"\xa7one"), (0, b"\xa7two")]   # SACK trailer stripped from ch0


def test_eight_byte_unreliable_ch0_refused():
    u, _ = _mk()
    try:
        u.send(0, b"\xa7" + b"\x00" * 7)
    except ValueError:
        pass
    else:
        raise AssertionError("8-byte unreliable ch0 send must be refused")
    u.send_heartbeat(b"\x00" * 8)                       # the sanctioned path
    u.send(0, b"\xa7" * 8, reliable=True)               # reliable is fine
    u.send(3, b"\xa7" * 8)                              # other channels are fine


def test_auto_ack_off_is_silent():
    u, _ = _mk()
    u.send_heartbeat(b"\x00" * 8)
    u.auto_ack = False
    n = len(u._sock.out)
    u.handle_datagram(_rel(0, b"\xa7x"))
    assert len(u._sock.out) == n


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for fn in tests:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
