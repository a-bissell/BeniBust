#!/usr/bin/env python3
"""beni_probe.py — no-shell diagnostics for a flashed Mondo/Beni robot.

Run this while joined to the robot's SoftAP (192.168.7.1) or its Home-LAN IP.
It answers the questions that decide what to do next, without needing SSH:

  * which TCP services are up on the robot (22 sshd, 23 telnet, 8010 config,
    8085 OTA/md_upgrade, 9007 UCP)
  * which firmware version / serial the running robot reports (over UCP)
  * whether md_upgrade's HTTP /health answers

Zero third-party SDK dependencies — everything here comes from this repo's `sdk/freewheel`.

Usage:
    python3 native-analysis/tools/beni_probe.py
    ... --host 192.168.7.1
    ... --expect 26.11.19.06      # warn if the running version differs

Interpretation (printed at the end):
    version == expected + :22 closed  -> new image is running, sshd failed to start
    version != expected               -> robot booted the other/old slot (or install didn't take)
    8010/8085/9007 all closed         -> /md services aren't up (boot/mount problem)
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

def _locate_sdk() -> Path:
    """Find the bundled `sdk/` directory from either layout.

    In the repo the script lives at `native-analysis/tools/`, so the SDK is two
    levels up; in the release zip it lives at `tools/`, one level up. Walk up
    until a `sdk/freewheel/` package is found rather than assuming a fixed depth.
    """
    env = os.environ.get("FREEWHEEL_SDK")
    if env and (Path(env) / "freewheel").is_dir():
        return Path(env)
    here = Path(__file__).resolve().parent
    for candidate in (here.parent / "sdk", here.parents[1] / "sdk", here) :
        if (candidate / "freewheel" / "__init__.py").is_file():
            return candidate
    for parent in here.parents:
        if (parent / "sdk" / "freewheel" / "__init__.py").is_file():
            return parent / "sdk"
    return here.parent / "sdk"


_SDK = _locate_sdk()
if str(_SDK) not in sys.path:
    sys.path.insert(0, str(_SDK))

from freewheel import MondoClient, ota  # noqa: E402

# TCP services. UCP (:9007) is UDP, so it is probed with the client, not a TCP connect.
DEFAULT_PORTS = (22, 23, 8010, 8085)


def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def http_health(host: str, port: int, bearer: str | None, timeout: float) -> dict[str, Any]:
    try:
        client = ota.MdUpgradeClient(host, port, scheme="auto", bearer_token=bearer, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}
    try:
        return {"scheme": client.scheme, "status": 200, "body": json.dumps(client.health())}
    except ota.MdUpgradeError as exc:
        return {"scheme": client.scheme, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"scheme": client.scheme, "error": f"{type(exc).__name__}: {exc}"}


def _decode_fixed(raw: Any, declared_len: int = 0) -> str:
    blob = bytes(raw or b"")
    n = int(declared_len or len(blob))
    return blob[:n].decode("utf-8", errors="replace").rstrip("\x00").strip()


def query_identity(host: str, ucp_port: int, timeout: float) -> dict[str, Any]:
    """Firmware version + serial over the UCP `/cmd` bus (passive: the robot stays locked)."""
    out: dict[str, Any] = {}
    client = MondoClient(host=host, port=ucp_port, log=lambda _m: None)
    try:
        client.connect()
        try:
            rsp = client.request("cmd/common/get_version_req", timeout=max(2.0, timeout))
            if rsp:
                d = rsp.get("data") or {}
                out["version"] = {
                    "major_version": int(d.get("majorVersion", 0) or 0),
                    "minor_version": int(d.get("minorVersion", 0) or 0),
                    "hardware_version": _decode_fixed(d.get("hardwareVersion")),
                    "loader_version": _decode_fixed(d.get("loaderVersion")),
                    "firmware_version": _decode_fixed(d.get("firmwareVersion")),
                    "is_mass_product": int(d.get("isMassProduct", 0) or 0),
                    "ret_code": int(d.get("retCode", 0) or 0),
                }
        except Exception as exc:  # noqa: BLE001
            out["version_error"] = f"{type(exc).__name__}: {exc}"
        try:
            sn = client.serial_number(timeout=max(2.0, timeout))
            if sn:
                out["serial"] = sn
        except Exception as exc:  # noqa: BLE001
            out["serial_error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        out["connect_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
    return out


def query_ota_task(host: str, port: int, state_file: str, bearer: str | None,
                   timeout: float) -> dict[str, Any]:
    """Look up the saved upgrade session's state on md_upgrade (SUCCEEDED = flashed+committed)."""
    try:
        state = json.loads(Path(state_file).expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"skipped": "no saved state"}
    upgrade_id = str(state.get("upgrade_id") or "")
    token = str(state.get("upload_token") or "")
    if not upgrade_id or not token:
        return {"skipped": "no upgrade_id/upload_token in state"}
    try:
        client = ota.MdUpgradeClient(host, port, scheme="auto", bearer_token=bearer, timeout=timeout)
        status, body = client._request(  # noqa: SLF001 — read-only diagnostic
            "GET", f"/v2/upgrades/{upgrade_id}",
            extra_headers={"Upload-Token": token}, timeout=timeout,
        )
        parsed: Any = json.loads(body) if body.strip().startswith("{") else body.strip()
        return {"upgrade_id": upgrade_id, "status": status, "body": parsed}
    except Exception as exc:  # noqa: BLE001
        return {"upgrade_id": upgrade_id, "error": f"{type(exc).__name__}: {exc}"}


def _norm(v: str) -> str:
    return (v or "").strip().lstrip("Vv")


def main() -> int:
    ap = argparse.ArgumentParser(description="No-shell diagnostics for a flashed Beni robot")
    ap.add_argument("--host", default="192.168.7.1", help="robot IP (SoftAP 192.168.7.1 or LAN IP)")
    ap.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS))
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--ucp-port", type=int, default=9007)
    ap.add_argument("--ota-port", type=int, default=8085)
    ap.add_argument("--expect", default="", help="expected firmware version, e.g. 26.11.19.06")
    ap.add_argument("--state-file", default=str(Path.home() / ".config" / "beni-flash" / "state.json"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    host = args.host
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    print(f"probing {host} ...", file=sys.stderr)

    open_ports = [p for p in ports if tcp_open(host, p, args.timeout)]
    ports_map = {str(p): (p in open_ports) for p in ports}

    result: dict[str, Any] = {"host": host, "ports": ports_map, "open_ports": open_ports}
    bearer = ota.resolve_media_token()

    if args.ota_port in open_ports:
        result["health"] = http_health(host, args.ota_port, bearer, args.timeout)

    # UCP :9007 is UDP — always try the client (a TCP probe would always look "closed").
    result["identity"] = query_identity(host, args.ucp_port, max(3.0, args.timeout))

    # If we have a saved OTA session, ask md_upgrade how the install actually ended.
    if args.ota_port in open_ports:
        result["ota_task"] = query_ota_task(host, args.ota_port, args.state_file, bearer, args.timeout)

    ver = ""
    ident = result.get("identity") or {}
    if isinstance(ident, dict) and isinstance(ident.get("version"), dict):
        ver = str(ident["version"].get("firmware_version") or "")

    # ---- human summary
    print()
    print("ports:")
    for p in ports:
        print(f"  {p:5d}  {'OPEN' if ports_map[str(p)] else 'closed'}")
    if "health" in result:
        print(f"md_upgrade /health: {result['health']}")
    if "ota_task" in result:
        print(f"ota task: {result['ota_task']}")
    print(f"running firmware: {ver or 'unknown'}")
    if isinstance(ident, dict):
        if ident.get("serial"):
            print(f"serial: {ident['serial']}")
        for k in ("version_error", "serial_error", "connect_error", "skipped"):
            if ident.get(k):
                print(f"({k}: {ident[k]})")

    ssdh_open = ports_map.get("22", False)
    md_up = any(ports_map.get(str(p), False) for p in (8010, 8085))
    print()
    if args.expect and ver and _norm(ver) != _norm(args.expect):
        print(f"WARNING: running {ver} but expected {args.expect} — the new slot may not be active.")
    elif args.expect and ver and _norm(ver) == _norm(args.expect):
        print(f"OK: running expected version {ver}.")
    if ssdh_open:
        print("sshd: port 22 is OPEN (test a real ssh handshake; 'kex_exchange' = broken).")
    elif md_up:
        print("sshd: port 22 CLOSED while md services are up — sshd did not start on this image.")
        print("      Next: UART root shell -> '/md/lib/md_sshd -r -t -f /md/etc/md_sshd_config'")
        print("      and 'pidof md_sshd; cat /etc/.config/md_app_autostart.conf'.")
    else:
        print("md services: 8010/8085 closed — /md apps aren't running (boot/mount/slot issue).")

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    return 0 if ssdh_open else 3


if __name__ == "__main__":
    raise SystemExit(main())
