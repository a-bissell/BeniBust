"""Encode `/cmd/*` protobuf payloads for the robot's control bus.

Schemas recovered statically from MondoApp v1.0.13's Dart (`libapp.so` via blutter):
the `md_device_protocol` generated protobuf messages. Every command/response is an
envelope `{ WireHeader header = 1; <X>Data data = 2; }`; the real fields live in the
`<X>Data` sub-message. Field tags/names/types and the topic→message map are in
`cmd_schemas.json` (the full `.proto` is kept in the research repository).

This is a minimal proto3 encoder driven by that schema — enough to build a `/cmd`
Put payload. Pair it with `MondoClient.publish()` (the zenoh send side). STATIC: the
schemas are read from the shipped app; not yet confirmed against a live robot.
"""
from __future__ import annotations

import json
import os
import struct
from typing import Any, Dict, Optional

_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cmd_schemas.json")
with open(_SCHEMA_PATH) as _f:
    _S = json.load(_f)
MESSAGES: Dict[str, list] = _S["messages"]           # name -> [{tag,name,wire}]
TOPIC_TO_MESSAGE: Dict[str, str] = _S["topic_to_message"]

# proto3 wire types
_WT_VARINT, _WT_I64, _WT_LEN, _WT_I32 = 0, 1, 2, 5
_VARINT = {"uint32", "uint64", "int32", "int64", "sint32", "sint64", "bool", "enum"}
_I64 = {"fixed64", "sfixed64", "double"}
_I32 = {"fixed32", "sfixed32", "float"}


class CmdProtoError(ValueError):
    pass


def _varint(v: int) -> bytes:
    v &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | 0x80 if v else b)
        if not v:
            return bytes(out)


def _zigzag(v: int, bits: int) -> int:
    return (v << 1) ^ (v >> (bits - 1))


def _base_type(wire: str) -> str:
    return wire[len("repeated "):] if wire.startswith("repeated ") else wire


def _scalar_bytes(wire: str, value: Any) -> (int, bytes):
    """Return (wire_type, encoded_value_without_tag) for a scalar field."""
    if wire.startswith("message<") or wire.startswith("enum<"):
        inner = wire[wire.index("<") + 1:-1]
        if wire.startswith("enum<"):
            return _WT_VARINT, _varint(int(value))
        return _WT_LEN, _len_delim(encode_message(inner, value))
    if wire in _VARINT:
        if wire == "bool":
            return _WT_VARINT, _varint(1 if value else 0)
        if wire == "sint32":
            return _WT_VARINT, _varint(_zigzag(int(value), 32))
        if wire == "sint64":
            return _WT_VARINT, _varint(_zigzag(int(value), 64))
        return _WT_VARINT, _varint(int(value))
    if wire in _I32:
        return (_WT_I32, struct.pack("<f", value) if wire == "float"
                else struct.pack("<i" if wire == "sfixed32" else "<I", int(value)))
    if wire in _I64:
        return (_WT_I64, struct.pack("<d", value) if wire == "double"
                else struct.pack("<q" if wire == "sfixed64" else "<Q", int(value)))
    if wire == "string":
        return _WT_LEN, _len_delim(value.encode("utf-8") if isinstance(value, str) else bytes(value))
    if wire == "bytes":
        return _WT_LEN, _len_delim(bytes(value))
    if wire == "unknown":
        raise CmdProtoError(
            "this field's tag/type is unrecovered (v1.0.85 dropped protobuf-dart "
            "reflection for custom codecs — field names recovered, wire types not). "
            "Can't encode it; recover the tag from a wire capture, or send fieldless.")
    raise CmdProtoError(f"unsupported wire type {wire!r}")


def _len_delim(b: bytes) -> bytes:
    return _varint(len(b)) + b


def _tag(field_no: int, wt: int) -> bytes:
    return _varint((field_no << 3) | wt)


def encode_message(msg_name: str, fields: Dict[str, Any]) -> bytes:
    """Encode a message by name from a {field_name: value} dict (proto3; unset
    fields omitted). Nested message values are dicts; repeated values are lists."""
    schema = MESSAGES.get(msg_name)
    if schema is None:
        raise CmdProtoError(f"unknown message {msg_name!r}")
    by_name = {f["name"]: f for f in schema}
    out = bytearray()
    for name, value in fields.items():
        f = by_name.get(name)
        if f is None:
            raise CmdProtoError(f"{msg_name} has no field {name!r} "
                                f"(fields: {', '.join(by_name)})")
        wire = f["wire"]
        if wire == "unknown" or "tag" not in f:
            raise CmdProtoError(
                f"{msg_name}.{name}: tag/type unrecovered (v1.0.85 dropped protobuf-dart "
                "reflection; this field name is recovered but its wire tag/type is not). "
                "Can't encode it — recover the tag from a wire capture, or send fieldless.")
        tag = f["tag"]
        if wire.startswith("repeated "):
            base = _base_type(wire)
            for el in value:
                wt, data = _scalar_bytes(base, el)
                out += _tag(tag, wt) + data
        else:
            wt, data = _scalar_bytes(wire, value)
            out += _tag(tag, wt) + data
    return bytes(out)


APP_PREFIX = "app/"          # client -> robot key prefix (official SDK + community SDK)
DEVICE_PREFIX = "device/"    # robot -> client key prefix

# Topics whose robot-side app bridge rejects `header` (drops frames if tag 1 is set).
HEADERLESS_TOPICS = frozenset({
    "data/audio/playback_data",
    "cmd/camera/unified_cmd",
    "cmd/camera/relative_trajectory_replay",
    "cmd/led/ctrl_oneway",
    "cmd/hms/action_request",
    "cmd/hms/action_response",
})

# Topics whose robot-side codec requires all proto3-optional scalar fields present.
EXPLICIT_ZERO_TOPICS = frozenset({
    "cmd/camera/unified_cmd",
    "cmd/ota/upgrade_control_req",
    "cmd/robot/sn_req",
    "cmd/nm/wifi_scan_req",
    "cmd/nm/wifi_connect_req",
    "cmd/nm/wifi_provision_start_req",
    "cmd/nm/wifi_provision_commit_req",
    "cmd/nm/wifi_provision_result_req",
    "cmd/nm/wifi_switch_to_ap_req",
    "cmd/nm/wifi_switch_to_station_req",
    "cmd/nm/wifi_switch_to_station_result_req",
})


def canonical_topic(keyexpr: str) -> str:
    """`app/cmd/x`, `device/cmd/x`, `/cmd/x`, `cmd/x` -> `cmd/x` (the schema key)."""
    t = keyexpr.lstrip("/")
    for p in (APP_PREFIX, DEVICE_PREFIX):
        if t.startswith(p):
            return t[len(p):]
    return t


def message_for_topic(topic: str) -> Optional[str]:
    """Resolve a `/cmd/*` topic (with or without leading slash) to its message."""
    return TOPIC_TO_MESSAGE.get(canonical_topic(topic))


def _zero_default(wire: str):
    if wire == "bool":
        return False
    if wire in ("float", "double"):
        return 0.0
    if wire in _VARINT or wire in _I32 or wire in _I64 or wire.startswith("enum<"):
        return 0
    return None


def build_cmd(topic: str, seq: int = 0, *, headerless: Optional[bool] = None,
              fill_defaults: Optional[bool] = None, **data_fields: Any) -> bytes:
    """Build the protobuf payload for a `/cmd/*` topic: the envelope
    `{header{seqNum:seq}, data{**data_fields}}`. `data_fields` are the `<X>Data`
    message's fields (see cmd-protobuf-schemas.proto). Returns the bytes to publish."""
    canon = canonical_topic(topic)
    msg = message_for_topic(canon)
    if msg is None:
        raise CmdProtoError(f"no message mapped for topic {topic!r}")
    if headerless is None:
        headerless = canon in HEADERLESS_TOPICS
    if fill_defaults is None:
        fill_defaults = canon in EXPLICIT_ZERO_TOPICS
    env = MESSAGES[msg]
    by_name = {f["name"]: f for f in env}
    parts = {}
    if "header" in by_name and not headerless:
        if canon.startswith("cmd/nm/"):
            import time as _time
            parts["header"] = {"seqNum": seq, "timestamp": int(_time.time() * 1000), "version": 1}
        else:
            parts["header"] = {"seqNum": seq}
    data_field = by_name.get("data")
    if data_field is None:
        # flat message (no data sub-message): fields go directly
        return encode_message(msg, {"seqNum": seq, **data_fields} if ("seqNum" in by_name and not headerless) else data_fields)
    data_msg = data_field["wire"][len("message<"):-1]
    if fill_defaults:
        merged: Dict[str, Any] = {}
        for df in MESSAGES.get(data_msg, ()):
            if "tag" not in df or df["wire"].startswith("repeated "):
                continue
            z = _zero_default(df["wire"])
            if z is not None:
                merged[df["name"]] = z
        merged.update(data_fields)
        parts["data"] = merged
    else:
        parts["data"] = data_fields
    # encode envelope: header is a nested message dict, data is nested message dict
    out = bytearray()
    for name in ("header", "data"):
        if name not in parts:
            continue
        f = by_name[name]
        inner = (encode_message("WireHeader", parts["header"]) if name == "header"
                 else encode_message(data_msg, parts["data"]))
        out += _tag(f["tag"], _WT_LEN) + _len_delim(inner)
    return bytes(out)


# ── decode (proto3, schema-driven) — for parsing /cmd responses ───────────────
def _rd_varint(b: bytes, i: int):
    v = s = 0
    while True:
        c = b[i]; i += 1
        v |= (c & 0x7F) << s
        if not c & 0x80:
            return v, i
        s += 7


def _unzigzag(v: int) -> int:
    return (v >> 1) ^ -(v & 1)


def decode_message(msg_name: str, data: bytes) -> dict:
    """Decode a message's bytes into {field_name: value} using the schema.
    Nested messages become dicts, repeated fields lists, unknown tags are kept
    under their number."""
    schema = MESSAGES.get(msg_name)
    if schema is None:
        raise CmdProtoError(f"unknown message {msg_name!r}")
    by_tag = {f["tag"]: f for f in schema if "tag" in f}   # names-only fields have no tag
    out: dict = {}
    i, n = 0, len(data)
    while i < n:
        key, i = _rd_varint(data, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            raw, i = _rd_varint(data, i)
        elif wt == 2:
            ln, i = _rd_varint(data, i)
            raw = data[i:i + ln]; i += ln
        elif wt == 5:
            raw = data[i:i + 4]; i += 4
        elif wt == 1:
            raw = data[i:i + 8]; i += 8
        else:
            raise CmdProtoError(f"bad wire type {wt}")
        f = by_tag.get(fn)
        if f is None:
            out.setdefault(f"#{fn}", raw)
            continue
        wire = _base_type(f["wire"])
        val = _interpret(wire, wt, raw)
        if f["wire"].startswith("repeated "):
            out.setdefault(f["name"], []).append(val)
        else:
            out[f["name"]] = val
    return out


def _interpret(wire: str, wt: int, raw):
    if wire.startswith("message<"):
        return decode_message(wire[len("message<"):-1], raw)
    if wire.startswith("enum<") or wire == "enum":
        return raw
    if wire in ("uint32", "uint64", "int32", "int64", "bool"):
        return bool(raw) if wire == "bool" else raw
    if wire in ("sint32", "sint64"):
        return _unzigzag(raw)
    if wire == "float":
        return struct.unpack("<f", raw)[0]
    if wire == "double":
        return struct.unpack("<d", raw)[0]
    if wire in ("fixed32", "sfixed32"):
        return struct.unpack("<i" if wire[0] == "s" else "<I", raw)[0]
    if wire in ("fixed64", "sfixed64"):
        return struct.unpack("<q" if wire[0] == "s" else "<Q", raw)[0]
    if wire == "string":
        return raw.decode("utf-8", "replace")
    return raw                                     # bytes


def decode_cmd(topic: str, payload: bytes) -> dict:
    """Decode a `/cmd/*` payload into {'seqNum': int, 'data': {...}}."""
    msg = message_for_topic(topic)
    if msg is None:
        raise CmdProtoError(f"no message mapped for topic {topic!r}")
    d = decode_message(msg, payload)
    header = d.get("header") or {}
    return {"seqNum": header.get("seqNum", 0), "data": d.get("data", {}), "raw": d}


def response_topic(req_topic: str) -> Optional[str]:
    """Map a request topic to its response topic by the app's naming convention."""
    t = canonical_topic(req_topic)
    if t == "status/hms/query_active":
        return "status/hms/active_snapshot"
    for a, b in (("_req", "_rsp"), ("request_ack", None), ("request", "request_ack"),
                 ("_cmd", "_cmd_ack")):
        if b and t.endswith(a):
            cand = t[:-len(a)] + b
            if cand in TOPIC_TO_MESSAGE:
                return cand
    if not t.endswith("_rsp") and (t + "_rsp") in TOPIC_TO_MESSAGE:
        return t + "_rsp"
    return None


def all_request_topics() -> list:
    """Every topic that has a response topic (i.e. is usable with `request()`)."""
    return sorted(t for t in TOPIC_TO_MESSAGE if response_topic(t) is not None)


def fields_of(topic_or_message: str) -> list:
    """Introspect: the `<X>Data` field list for a topic (or a message name)."""
    msg = message_for_topic(topic_or_message) or topic_or_message
    env = MESSAGES.get(msg, [])
    data = next((f for f in env if f["name"] == "data"), None)
    if data and data["wire"].startswith("message<"):
        return MESSAGES.get(data["wire"][len("message<"):-1], [])
    return env
