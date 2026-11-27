"""Control-packet encoding for the Mondo robot (clean-room, from static RE).

Reference: native-analysis/control-packet.md. The drive payload is an 8-byte
little-endian u64 of bit-packed fields. Scaling mirrors the app's `_map2000` /
`_map62`. The `ControlState.to_bytes()` path also replicates the app's `isLock`
safety override so our wire output matches `packControl` exactly.

STATIC-ONLY: verified against the decompiled packer, not against hardware.
"""
from __future__ import annotations

import math
from dataclasses import dataclass


def _clamp(v: float, lo: float, hi: float) -> float:
    return lo if v < lo else hi if v > hi else v


def _round_half_away(x: float) -> int:
    # C round(): half away from zero. Domain here is always >= 0, so floor(x+0.5).
    return int(math.floor(x + 0.5))


def map2000(v: float) -> int:
    """norm [-1.0, 1.0] -> int [0, 2000], neutral 0.0 -> 1000 (bits 0-10/11-21/22-32)."""
    x = _clamp(v, -1.0, 1.0) * 1000.0 + 1000.0
    return int(_clamp(_round_half_away(x), 0, 2000))


def map62(v: float) -> int:
    """norm [-1.0, 1.0] -> int [0, 62], neutral 0.0 -> 31 (bits 33-38/39-44)."""
    x = _clamp(v, -1.0, 1.0) * 31.0 + 31.0
    return int(_clamp(_round_half_away(x), 0, 62))


# --- Physical command ranges, cross-referenced with Mondo open-beni (MIT) ------
# open-beni defines the command space the robot's ONBOARD policy consumes. These
# map our normalized axes to physical units. THE AXIS ASSIGNMENT IS A HYPOTHESIS
# to confirm on hardware; `roll` and `channel2`=gimbal-yaw are the high-confidence
# anchors (field-name match; app's allow_locked_gimbal_yaw ↔ open-beni gimbal cmd).
LIN_VEL_X_MAX = 2.0     # m/s      channel0  (open-beni lin_vel_x -2..2)
ANG_VEL_Z_MAX = 5.0     # rad/s    channel1  (open-beni ang_vel_z -5..5)
GIMBAL_YAW_MAX = 5.0    # rad      channel2  (open-beni gimbal yaw -5..5)
PITCH_MAX = 0.1         # rad      channel3  (open-beni base_pitch -0.1..0.1)
ROLL_MAX = 0.1          # rad      roll      (open-beni base_roll  -0.1..0.1)
HEIGHT_MIN_M = 0.10     # m        height=0  (open-beni base_height 0.10..0.12)
HEIGHT_MAX_M = 0.12     # m        height=31


def height_m_to_field(height_m: float) -> int:
    """Base height in metres (0.10..0.12) -> 5-bit field 0..31."""
    frac = (height_m - HEIGHT_MIN_M) / (HEIGHT_MAX_M - HEIGHT_MIN_M)
    return int(_clamp(round(frac * 31), 0, 31))


def twist_to_axes(vx: float = None, wz: float = None, gimbal_yaw: float = None,
                  pitch: float = None, roll: float = None,
                  height_m: float = None) -> dict:
    """Convert physical commands (open-beni units) into ControlState field values
    (normalized axes + height field). Only provided args are returned.

    vx m/s, wz rad/s, gimbal_yaw rad, pitch rad, roll rad, height_m metres.
    UNCONFIRMED axis mapping — validate on hardware / in the open-beni sim.
    """
    out: dict = {}
    if vx is not None:
        out["ch0"] = _clamp(vx / LIN_VEL_X_MAX, -1.0, 1.0)
    if wz is not None:
        out["ch1"] = _clamp(wz / ANG_VEL_Z_MAX, -1.0, 1.0)
    if gimbal_yaw is not None:
        out["ch2"] = _clamp(gimbal_yaw / GIMBAL_YAW_MAX, -1.0, 1.0)
    if pitch is not None:
        out["ch3"] = _clamp(pitch / PITCH_MAX, -1.0, 1.0)
    if roll is not None:
        out["roll"] = _clamp(roll / ROLL_MAX, -1.0, 1.0)
    if height_m is not None:
        out["height"] = height_m_to_field(height_m)
    return out


def fields_to_twist(f: dict) -> dict:
    """Inverse of twist_to_axes for the decode side (virtual robot / telemetry):
    raw unpacked fields (from unpack_control) -> physical commands.

    Neutral is 1000 for 11-bit axes and 31 for 6-bit axes. UNCONFIRMED mapping."""
    return {
        "vx": (f["channel0"] - 1000) / 1000.0 * LIN_VEL_X_MAX,
        "wz": (f["channel1"] - 1000) / 1000.0 * ANG_VEL_Z_MAX,
        "gimbal_yaw": (f["channel2"] - 1000) / 1000.0 * GIMBAL_YAW_MAX,
        "pitch": (f["channel3"] - 31) / 31.0 * PITCH_MAX,
        "roll": (f["roll"] - 31) / 31.0 * ROLL_MAX,
        "height_m": HEIGHT_MIN_M + f["height"] / 31.0 * (HEIGHT_MAX_M - HEIGHT_MIN_M),
        "jump": bool(f["jump_cmd"]) or f["flip_cmd"] > 0,
        "islock": bool(f["islock"]),
        "ispause": bool(f["ispause"]),
        "max_speed": f["max_speed"],
    }


def pack_control(
    ch0: float = 0.0, ch1: float = 0.0, ch2: float = 0.0,
    ch3: float = 0.0, roll: float = 0.0,
    height: int = 0, jump_cmd: bool = False, flip_cmd: int = 0,
    max_speed: int = 0, nav_flag: int = 0,
    ispause: bool = False, islock: bool = False,
    min_turn_mode: bool = False, third_person_mode: bool = False,
    jump_mode: bool = False, video_enabled: bool = True,
) -> bytes:
    """Pack raw field values into the 8-byte LE control word. No isLock gating
    here — that lives in ControlState.to_bytes(). Axis args are normalized floats."""
    w = map2000(ch0)
    w |= map2000(ch1) << 11
    w |= map2000(ch2) << 22
    w |= map62(ch3) << 33
    w |= map62(roll) << 39
    w |= (int(_clamp(height, 0, 31)) & 0x1F) << 45
    w |= (1 if jump_cmd else 0) << 50
    w |= (int(_clamp(flip_cmd, 0, 4)) & 0x7) << 51
    w |= (int(_clamp(max_speed, 0, 2)) & 0x3) << 54
    w |= (nav_flag & 0x3) << 56
    w |= (1 if ispause else 0) << 58
    w |= (1 if islock else 0) << 59
    w |= (1 if min_turn_mode else 0) << 60
    w |= (1 if third_person_mode else 0) << 61
    w |= (1 if jump_mode else 0) << 62
    w |= (0 if video_enabled else 1) << 63
    return w.to_bytes(8, "little")


@dataclass
class ControlState:
    """Mutable control state. Axes are normalized floats in [-1.0, 1.0]."""
    ch0: float = 0.0           # analog axis (physical mapping TBD on hardware)
    ch1: float = 0.0
    ch2: float = 0.0           # gimbal yaw (held unless allow_locked_gimbal_yaw)
    ch3: float = 0.0
    roll: float = 0.0
    height: int = 0            # 0..31
    max_speed: int = 0         # 0..2  (0 = no motion)
    nav_flag: int = 0          # 0..3  (meaning TBD)
    flip_cmd: int = 0          # 0..4
    jump_cmd: bool = False
    ispause: bool = False      # emergency stop
    islock: bool = True        # SAFE DEFAULT: locked until you unlock()
    min_turn_mode: bool = False
    third_person_mode: bool = False
    jump_mode: bool = False
    video_enabled: bool = True
    allow_locked_gimbal_yaw: bool = False

    def to_bytes(self) -> bytes:
        """Encode to the 8-byte wire word, applying the app's isLock override so
        output matches `packControl`."""
        if self.islock:
            ch2 = self.ch2 if (self.allow_locked_gimbal_yaw and not self.ispause) else 0.0
            return pack_control(
                ch0=0.0, ch1=0.0, ch2=ch2, ch3=0.0, roll=0.0,
                height=self.height, jump_cmd=False, flip_cmd=0, max_speed=0,
                nav_flag=self.nav_flag, ispause=self.ispause, islock=True,
                min_turn_mode=False, third_person_mode=False, jump_mode=False,
                video_enabled=self.video_enabled,
            )
        return pack_control(
            ch0=self.ch0, ch1=self.ch1, ch2=self.ch2, ch3=self.ch3, roll=self.roll,
            height=self.height, jump_cmd=self.jump_cmd, flip_cmd=self.flip_cmd,
            max_speed=self.max_speed, nav_flag=self.nav_flag, ispause=self.ispause,
            islock=False, min_turn_mode=self.min_turn_mode,
            third_person_mode=self.third_person_mode, jump_mode=self.jump_mode,
            video_enabled=self.video_enabled,
        )


def unpack_control(data: bytes) -> dict:
    """Inverse of pack_control for debugging/telemetry (returns raw int fields)."""
    if len(data) != 8:
        raise ValueError("control payload must be 8 bytes")
    w = int.from_bytes(data, "little")
    def f(shift, mask): return (w >> shift) & mask
    return {
        "channel0": f(0, 0x7FF), "channel1": f(11, 0x7FF), "channel2": f(22, 0x7FF),
        "channel3": f(33, 0x3F), "roll": f(39, 0x3F), "height": f(45, 0x1F),
        "jump_cmd": f(50, 1), "flip_cmd": f(51, 0x7), "max_speed": f(54, 0x3),
        "nav_flag": f(56, 0x3), "ispause": f(58, 1), "islock": f(59, 1),
        "min_turn_mode": f(60, 1), "third_person_mode": f(61, 1),
        "jump_mode": f(62, 1), "no_liveview": f(63, 1),
    }
