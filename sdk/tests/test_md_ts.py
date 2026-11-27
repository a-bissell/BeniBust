#!/usr/bin/env python3
"""MD-TS (secure_v2) session tests (python -m tests.test_md_ts).

Known-answer vectors come from the community cross-check
(tests/crosscheck/vectors.json); the rest checks behaviour: tamper/replay
rejection, robot errors, and identity files. Needs `cryptography`."""
import json
import os
import stat
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from freewheel import md_ts as m                                    # noqa: E402

B = bytes.fromhex
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "crosscheck", "vectors.json")) as _fh:
    V = json.load(_fh)["md_ts"]


def _vec_identity():
    return m.Identity(B(V["client_id"]), V["key_version"], B(V["client_static_priv"]),
                      B(V["client_static_pub"]), B(V["robot_static_pub"]))


def _vec_pair():
    ident = _vec_identity()
    hs = m.ClientHandshake(ident, client_nonce=B(V["client_nonce"]))
    r = m.Responder(B(V["robot_static_priv"]), {ident.client_id: ident.public_key},
                    server_nonce=B(V["server_nonce"]), channel_id=B(V["channel_id"]))
    return ident, hs, r


def _complete(hs, r):
    msgs = [hs.start()]
    while msgs:
        out = []
        for env in msgs:
            rep = r.handle(env)
            if rep is not None:
                out += hs.handle(rep)
        msgs = out
    assert hs.done and r.session is not None
    return hs.session, r.session


# ── known-answer vectors (community cross-check) ─────────────────────────────
def test_kat_handshake_and_records():
    ident, hs, r = _vec_pair()
    assert m.x25519_public(ident.private_key) == ident.public_key
    start = hs.start()
    assert start.hex() == V["zenoh_hs_envelope_session_start"]
    challenge = r.handle(start)
    assert m.decode_envelope(challenge) == ("handshake", B(V["hs_session_challenge"]))
    (confirm,) = hs.handle(challenge)
    assert m.decode_envelope(confirm) == ("encrypted", B(V["client_confirm_record"]))
    server_confirm = r.handle(confirm)
    assert m.decode_envelope(server_confirm) == ("encrypted", B(V["server_confirm_record"]))
    assert hs.handle(server_confirm) == [] and hs.done
    assert hs.session.transcript_hash.hex() == V["transcript_hash"]
    sp = V["sealed_payload"]
    assert hs.session.seal(sp["keyexpr"], B(sp["plaintext"])).hex() == sp["seq1_envelope"]
    assert hs.session.seal(sp["keyexpr"], B(sp["plaintext"])).hex() == sp["seq2_envelope"]
    assert m.zenoh_aad(0, B(V["channel_id"]), 1, sp["keyexpr"]).hex() == V["zenoh_aad_seq1"]


def test_kat_key_schedule():
    th = m.transcript_hash(transport=2, client_id=B(V["client_id"]), key_version=V["key_version"],
                           client_pub=B(V["client_static_pub"]), robot_pub=B(V["robot_static_pub"]),
                           client_nonce=B(V["client_nonce"]), server_nonce=B(V["server_nonce"]),
                           channel_id=B(V["channel_id"]))
    kc, ks = m.derive_keys(B(V["shared_secret"]), B(V["client_nonce"]), B(V["server_nonce"]), 2, th)
    assert (th.hex(), kc.hex(), ks.hex()) == (V["transcript_hash"], V["key_c2s"], V["key_s2c"])


# ── envelope ─────────────────────────────────────────────────────────────────
def test_envelope_vs_plaintext():
    assert m.decode_envelope(bytes.fromhex("0a0208011200")) is None        # header{seq=1}, data{}
    assert m.decode_envelope(bytes.fromhex("120308e807")) is None          # RcJoystick
    assert m.decode_envelope(m.encode_hs_envelope(b"\x01" * 30)) == ("handshake", b"\x01" * 30)
    assert m.decode_envelope(m.encode_enc_envelope(b"\x02" * 40)) == ("encrypted", b"\x02" * 40)
    big = b"\x03" * 300                                                    # 2-byte length varint
    assert m.decode_envelope(m.encode_enc_envelope(big)) == ("encrypted", big)
    assert m.decode_envelope(b"") is None and m.decode_envelope(b"\x2a\x05\x01") is None


# ── AEAD rejection ───────────────────────────────────────────────────────────
def test_tamper_wrong_key_and_direction_rejected():
    _, hs, r = _vec_pair()
    cli, srv = _complete(hs, r)
    env = cli.seal("app/cmd/common/ping_req", b"hello")
    assert srv.open("app/cmd/common/ping_req", m.decode_envelope(env)[1]) == b"hello"
    flipped = bytearray(m.decode_envelope(cli.seal("app/cmd/common/ping_req", b"x"))[1])
    flipped[-1] ^= 1                                                        # bit flip in the tag
    _raises("AUTH_FAILED", lambda r_: srv.open("app/cmd/common/ping_req", r_), bytes(flipped))
    rec = m.decode_envelope(cli.seal("app/cmd/a_req", b"y"))[1]
    _raises("AUTH_FAILED", lambda r_: srv.open("app/cmd/b_req", r_), rec)   # keyexpr is authenticated
    rec = m.decode_envelope(cli.seal("k", b"z"))[1]
    _raises("AUTH_FAILED", lambda r_: cli.open("k", r_), rec)               # own direction ≠ peer's


def test_replay_window():
    _, hs, r = _vec_pair()
    cli, srv = _complete(hs, r)
    recs = [m.decode_envelope(cli.seal("k", bytes([i])))[1] for i in range(5)]
    assert srv.open("k", recs[2], check_replay=False) == b"\x02"            # peek: not consumed
    for i in (2, 0, 4, 1):                                                  # out of order is fine
        assert srv.open("k", recs[i]) == bytes([i])
    _raises("REPLAY", lambda r_: srv.open("k", r_), recs[2])
    assert srv.open("k", recs[3]) == b"\x03"
    srv._rx_max = 5000                                                      # far ahead
    _raises("REPLAY", lambda r_: srv.open("k", r_), recs[0])


def _raises(code, fn, *a):
    try:
        fn(*a)
    except m.MdTsError as e:
        assert e.code == code, e.code
        return e
    raise AssertionError(f"expected MdTsError {code}")


# ── robot errors / negotiation policy ────────────────────────────────────────
def test_unauthorized_client_raises_with_pairing_hint():
    ident = m.Identity.generate()
    r = m.Responder(m.random_nonzero(32), authorized={})
    hs = m.ClientHandshake(ident, robot_public_key=r.public_key)
    e = _raises("UNAUTHORIZED_CLIENT", hs.handle, r.handle(hs.start()))
    assert "freewheel.ble pair" in e.hint and "external" not in e.hint.lower()


def test_missing_robot_key_raises():
    ident = m.Identity.generate()
    r = m.Responder(m.random_nonzero(32), {ident.client_id: ident.public_key})
    hs = m.ClientHandshake(ident)                                           # no robot key known
    _raises("MISSING_ROBOT_KEY", hs.handle, r.handle(hs.start()))


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _silent(clock):
    def recv(t):
        clock.t += t
        return None
    return recv


def test_negotiate_auto_falls_back_md_ts_times_out():
    ident = m.Identity.generate()
    sent = []
    clk = _Clock()
    assert m.negotiate(ident, sent.append, _silent(clk), robot_public_key=b"\x01" * 32,
                       mode="auto", clock=clk) is None
    assert len(sent) >= 2 and all(m.decode_envelope(x)[0] == "handshake" for x in sent)  # re-sent
    clk2 = _Clock()
    _raises("HANDSHAKE_TIMEOUT", lambda: m.negotiate(ident, lambda e: None, _silent(clk2),
                                                      robot_public_key=b"\x01" * 32, mode="md-ts",
                                                      clock=clk2))


def test_negotiate_completes_over_queues():
    ident = m.Identity.generate()
    r = m.Responder(m.random_nonzero(32), {ident.client_id: ident.public_key})
    inbox = []
    sess = m.negotiate(ident, lambda env: inbox.append(r.handle(env)),
                       lambda t: inbox.pop(0) if inbox else None, robot_public_key=r.public_key)
    assert sess is not None and sess.confirmed and r.session is not None
    assert r.session.open("app/x", m.decode_envelope(sess.seal("app/x", b"ok"))[1]) == b"ok"


# ── identity files ───────────────────────────────────────────────────────────
def test_identity_legacy_format_roundtrip_and_overwrite_guard():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "identity.json")
    legacy_doc = {"client_id_hex": V["client_id"], "key_version": 1,
                "private_key_hex": V["client_static_priv"], "public_key_hex": V["client_static_pub"],
                "default_robot_public_key_hex": V["robot_static_pub"],
                "known_robots": {"ssid:Beni-000000": {"public_key_hex": V["robot_static_pub"]}}}
    with open(p, "w") as fh:
        json.dump(legacy_doc, fh)
    ident = m.Identity.load(p)
    assert ident.client_id.hex() == V["client_id"] and ident.robot_public_key.hex() == V["robot_static_pub"]
    ident.save(p)                                                           # same identity: allowed
    other = m.Identity.generate()
    _raises("IDENTITY_EXISTS", other.save, p)
    q = other.save(os.path.join(d, "sub", "fw.json"))
    assert stat.S_IMODE(os.stat(q).st_mode) == 0o600
    assert m.Identity.load(q).private_key == other.private_key


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in tests:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
