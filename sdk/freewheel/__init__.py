"""Freewheel — clean-room UCP control SDK for the Mondo BENI robot.

Reverse-engineered statically from MondoApp v1.0.13; the analysis lives in the
separate research repository.
Untested against hardware; see README.md for the assumptions to verify first.
"""
from .client import MondoClient
from .control import (ControlState, pack_control, unpack_control, map2000, map62,
                      twist_to_axes, fields_to_twist, height_m_to_field)
from .diagnostics import RxMonitor
from .transport import UcpTransport
from .zenoh import (ZenohLink, ZenohMonitor, ZenohPublisher, ZenohFrame, FrameType,
                    iter_frames, encode_connect, encode_ready, encode_close, encode_data,
                    keyexpr_candidates)
from .zenoh_pico import (ZenohPicoDecoder, Put, Del, DeclareKeyExpr, Encoding,
                         Timestamp, decode_batch as decode_zenoh_batch,
                         encode_put, encode_del, encode_frame, encode_declare_subscriber)
from . import cmd_proto, zenoh_session, capture, conformance, probe, tracking, fwextract, ext4
from .fwextract import extract_from_pcap, extract_from_http, FirmwarePart
from .cmd_proto import build_cmd, decode_cmd, message_for_topic, response_topic
from .capture import Capture, read_capture, decode_capture, summarize
from .conformance import check_capture
from .ext4 import Ext4Image
from .probe import Probe, ProbeReport
from .tracking import TrackingMonitor, TrackingState

__all__ = [
    "MondoClient", "ControlState", "pack_control", "unpack_control",
    "map2000", "map62", "twist_to_axes", "fields_to_twist", "height_m_to_field",
    "UcpTransport", "RxMonitor",
    "ZenohLink", "ZenohMonitor", "ZenohPublisher", "ZenohFrame", "FrameType",
    "iter_frames", "encode_connect", "encode_ready", "encode_close", "encode_data",
    "keyexpr_candidates",
    "ZenohPicoDecoder", "Put", "Del", "DeclareKeyExpr", "Encoding", "Timestamp",
    "decode_zenoh_batch", "encode_put", "encode_del", "encode_frame",
    "encode_declare_subscriber",
    "cmd_proto", "build_cmd", "decode_cmd", "message_for_topic", "response_topic",
    "zenoh_session", "ble",
    "BleDeviceInfo", "BleError", "BleFrame", "BlePairingResult", "BleStreamParser",
    "SimBlePeripheral", "SoftApCredentials", "pair_and_get_softap", "scan_ble", "setup_robot_wifi",
    "capture", "conformance", "probe", "tracking", "fwextract", "ext4", "ota",
    "Capture", "read_capture", "decode_capture", "summarize", "check_capture",
    "Probe", "ProbeReport", "TrackingMonitor", "TrackingState",
    "extract_from_pcap", "extract_from_http", "FirmwarePart",
    "Ext4Image",
]
__version__ = "0.0.1"


def __getattr__(name: str):
    import importlib
    if name == "ble":
        return importlib.import_module(".ble", __name__)
    if name in {
        "BleDeviceInfo", "BleError", "BleFrame", "BlePairingResult", "BleStreamParser",
        "SimBlePeripheral", "SoftApCredentials", "pair_and_get_softap", "scan_ble", "setup_robot_wifi",
    }:
        _ble = importlib.import_module(".ble", __name__)
        return getattr(_ble, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
