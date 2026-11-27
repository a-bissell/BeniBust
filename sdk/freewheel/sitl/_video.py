"""Synthetic H.265 for the simulated robot's video channel.

Only the clip generator the responder needs: a small Annex-B loop built once by
`ffmpeg` and cached. Decoding, the HTTP video hub and the browser assets stay in
the research repository.
"""
from __future__ import annotations

import shutil
import subprocess
import threading
from typing import List, Optional

_SIM_CLIP_CACHE: Optional[List[bytes]] = None
_SIM_CLIP_LOCK = threading.Lock()


def generate_sim_h265_clip() -> List[bytes]:
    """Build a small 16-frame 320x180 Annex-B H.265 loop via `ffmpeg` (cached).
    Returns `[]` when `ffmpeg` or `libx265` is unavailable."""
    global _SIM_CLIP_CACHE
    with _SIM_CLIP_LOCK:
        if _SIM_CLIP_CACHE is not None:
            return list(_SIM_CLIP_CACHE)
        if not shutil.which("ffmpeg"):
            _SIM_CLIP_CACHE = []
            return []
        try:
            r = subprocess.run(
                [
                    "ffmpeg", "-loglevel", "error",
                    "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=10:duration=1.6",
                    "-c:v", "libx265", "-preset", "ultrafast", "-tune", "zerolatency",
                    "-x265-params", "keyint=4:min-keyint=4:repeat-headers=1:bframes=0:aud=1",
                    "-pix_fmt", "yuv420p", "-f", "hevc", "pipe:1",
                ],
                capture_output=True,
                timeout=5.0,
                check=True,
            )
            parts = r.stdout.split(b"\x00\x00\x00\x01\x46")
            _SIM_CLIP_CACHE = [b"\x00\x00\x00\x01\x46" + p for p in parts[1:] if p]
        except Exception:  # noqa: BLE001
            _SIM_CLIP_CACHE = []
        return list(_SIM_CLIP_CACHE)
