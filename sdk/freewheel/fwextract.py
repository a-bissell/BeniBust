"""Carve the firmware package out of a day-one OTA capture (see docs/ota.md).

Path (B) of the OTA capture plan: the app POSTs the raw firmware **.zip** to the
robot's LAN upload server at `http://192.168.7.1:16170/v2/upgrades/…` as a
**plain-HTTP multipart/form-data** body. This reassembles that TCP stream from a
pcap and pulls the uploaded file out of the multipart body.

    python -m freewheel.fwextract capture.pcap -o firmware.zip
    python -m freewheel.fwextract capture.pcap --sha256 <expected>   # verify

Two layers, so it's robust to however you captured:
  • extract_from_http(bytes)  — pull the file out of one raw HTTP request (headers +
    multipart body). Use this if you already have the reassembled request (e.g.
    Wireshark → Follow TCP Stream → Save as, or `tshark -z follow,tcp,raw`).
  • extract_from_pcap(path)   — classic-pcap reader + minimal TCP reassembly that
    finds the HTTP POST/PUT stream(s) and runs the above on each.

NOT the firmware transport you'd find in a Freewheel `.fwcap` — that's the UCP
control link on :9007; the firmware bytes are a separate TCP flow on :16170.

Limitations (it's a focused carver, not Wireshark): classic pcap only (convert a
.pcapng with `editcap -F pcap in out`, or `tshark -F pcap`); Ethernet / Linux-SLL /
raw-IP / loopback link types; IPv4 + TCP. A monitor-mode **WPA** capture is
encrypted 802.11 — decrypt it first (Wireshark with the PSK) and export to a plain
pcap, or just capture from a host joined to the robot AP.
"""
from __future__ import annotations

import hashlib
import io
import struct
import zipfile
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

ZIP_MAGIC = b"PK\x03\x04"
UPLOAD_PORT = 16170                         # robot LAN firmware upload server
_HTTP_METHODS = (b"POST ", b"PUT ", b"GET ", b"PATCH ")


# ── result ─────────────────────────────────────────────────────────────────────
@dataclass
class FirmwarePart:
    field_name: str
    filename: str
    content_type: str
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def is_zip(self) -> bool:
        return self.data[:4] == ZIP_MAGIC and zipfile.is_zipfile(io.BytesIO(self.data))

    def zip_names(self, limit: int = 40) -> List[str]:
        if not self.is_zip:
            return []
        with zipfile.ZipFile(io.BytesIO(self.data)) as z:
            return z.namelist()[:limit]

    def summary(self) -> str:
        head = (f"{self.filename or self.field_name or '<file>'}  "
                f"{self.size} B  sha256={self.sha256}")
        if self.is_zip:
            names = self.zip_names()
            body = "\n".join(f"    {n}" for n in names)
            more = "" if len(names) < 40 else "\n    …"
            return f"{head}  [valid zip, {len(names)} entries]\n{body}{more}"
        enc = "  (not a zip — ENCRYPTED mode? or wrong stream)" if self.data[:4] != ZIP_MAGIC else ""
        return head + enc


# ── HTTP / multipart ───────────────────────────────────────────────────────────
def _split_headers(req: bytes) -> Tuple[bytes, bytes]:
    i = req.find(b"\r\n\r\n")
    if i < 0:
        return req, b""
    return req[:i], req[i + 4:]


def _header_value(headers: bytes, name: bytes) -> Optional[bytes]:
    low = headers.lower()
    key = name.lower() + b":"
    i = low.find(key)
    if i < 0:
        return None
    j = headers.find(b"\r\n", i)
    val = headers[i + len(key): j if j >= 0 else None]
    return val.strip()


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(body):
        nl = body.find(b"\r\n", i)
        if nl < 0:
            break
        try:
            n = int(body[i:nl].split(b";")[0], 16)
        except ValueError:
            break
        if n == 0:
            break
        start = nl + 2
        out += body[start:start + n]
        i = start + n + 2
    return bytes(out)


def _parse_disposition(part_headers: bytes) -> Tuple[str, str]:
    cd = _header_value(part_headers, b"Content-Disposition") or b""
    name = filename = ""
    for tok in cd.split(b";"):
        tok = tok.strip()
        if tok.startswith(b"name="):
            name = tok[5:].strip(b'"').decode("latin1", "replace")
        elif tok.startswith(b"filename="):
            filename = tok[9:].strip(b'"').decode("latin1", "replace")
    return name, filename


def extract_from_http(data: bytes) -> List[FirmwarePart]:
    """Pull every file part out of one raw HTTP request (multipart/form-data)."""
    headers, body = _split_headers(data)
    ctype = _header_value(headers, b"Content-Type") or b""
    if b"multipart/form-data" not in ctype.lower():
        # not multipart: if the whole body is a zip, treat it as the file
        if body[:4] == ZIP_MAGIC:
            return [FirmwarePart("", "", "application/zip", body)]
        return []
    bi = ctype.lower().find(b"boundary=")
    if bi < 0:
        return []
    boundary = ctype[bi + 9:].split(b";")[0].strip().strip(b'"')
    if (te := _header_value(headers, b"Transfer-Encoding")) and b"chunked" in te.lower():
        body = _dechunk(body)
    sep = b"--" + boundary
    parts: List[FirmwarePart] = []
    for chunk in body.split(sep):
        if chunk in (b"", b"--", b"--\r\n") or chunk.startswith(b"--"):
            continue
        chunk = chunk[2:] if chunk.startswith(b"\r\n") else chunk
        ph, pcontent = _split_headers(chunk)
        if pcontent.endswith(b"\r\n"):
            pcontent = pcontent[:-2]
        name, filename = _parse_disposition(ph)
        pct = (_header_value(ph, b"Content-Type") or b"").decode("latin1", "replace")
        # a file part: has a filename, or declares octet-stream/zip, or IS a zip
        if filename or "octet-stream" in pct or "zip" in pct or pcontent[:4] == ZIP_MAGIC:
            parts.append(FirmwarePart(name, filename, pct, pcontent))
    return parts


# ── pcap reader + TCP reassembly ────────────────────────────────────────────────
_LINKTYPE_IP_OFFSET = {
    1: ("eth", 14),        # Ethernet (VLAN handled below)
    113: ("sll", 16),      # Linux cooked
    101: ("raw", 0),       # raw IP
    12: ("raw", 0), 14: ("raw", 0),
    0: ("null", 4),        # BSD loopback (4-byte family)
}


def _open_pcap(path: str):
    fh = open(path, "rb")
    magic = fh.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        fh.close()
        raise NotImplementedError(
            "pcapng not supported — convert first: `editcap -F pcap in.pcapng out.pcap` "
            "(or `tshark -F pcap -r in.pcapng -w out.pcap`)")
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        fh.close()
        raise ValueError(f"not a classic pcap (magic {magic.hex()})")
    rest = fh.read(20)                       # ver, zone, sigfigs, snaplen, network
    network = struct.unpack(endian + "I", rest[16:20])[0]
    return fh, endian, network


def _iter_ip(path: str) -> Iterator[bytes]:
    fh, endian, network = _open_pcap(path)
    kind, off = _LINKTYPE_IP_OFFSET.get(network, (None, None))
    if kind is None:
        fh.close()
        raise NotImplementedError(
            f"link type {network} unsupported (need Ethernet/SLL/raw-IP/loopback; "
            "a monitor-mode 802.11 capture must be decrypted + exported first)")
    rec = struct.Struct(endian + "IIII")
    try:
        while True:
            hdr = fh.read(16)
            if len(hdr) < 16:
                break
            _s, _u, incl, _orig = rec.unpack(hdr)
            frame = fh.read(incl)
            if len(frame) < incl:
                break
            o = off
            if kind == "eth":
                if len(frame) < 14:
                    continue
                eth = struct.unpack(">H", frame[12:14])[0]
                if eth == 0x8100:            # VLAN tag
                    eth = struct.unpack(">H", frame[16:18])[0]
                    o = 18
                if eth != 0x0800:            # IPv4 only
                    continue
            yield frame[o:]
    finally:
        fh.close()


def _reassemble_tcp(path: str) -> List[bytes]:
    """Return the reassembled client→server payload of each TCP stream carrying an
    HTTP request. Keyed by 4-tuple; uses seq offsets (wrap-safe)."""
    segs: dict = {}        # 4-tuple -> list[(seq, payload)]
    for ip in _iter_ip(path):
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:     # protocol 6 = TCP
            continue
        src = ".".join(map(str, ip[12:16]))
        dst = ".".join(map(str, ip[16:20]))
        tcp = ip[ihl:]
        sport, dport, seq = struct.unpack(">HHI", tcp[0:8])
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if payload:
            segs.setdefault((src, sport, dst, dport), []).append((seq, payload))

    streams: List[bytes] = []
    for lst in segs.values():
        # base = lowest seq in the stream (assumes no 32-bit wrap within a stream,
        # which holds for < 2 GB — fine for a firmware upload).
        base = min(s for s, _ in lst)
        out = bytearray()
        for seq, seg in sorted(lst):
            off = seq - base
            if off > len(out):                   # gap — best effort, pad
                out += b"\x00" * (off - len(out))
            out[off:off + len(seg)] = seg
        data = bytes(out)
        if data[:5] in _HTTP_METHODS or data[:4] in _HTTP_METHODS:
            streams.append(data)
    return streams


def extract_from_pcap(path: str) -> List[FirmwarePart]:
    """Carve firmware file parts from every HTTP upload stream in a classic pcap."""
    out: List[FirmwarePart] = []
    for req in _reassemble_tcp(path):
        out.extend(extract_from_http(req))
    return out


# ── CLI ──────────────────────────────────────────────────────────────────────
def _pick_firmware(parts: List[FirmwarePart]) -> Optional[FirmwarePart]:
    if not parts:
        return None
    zips = [p for p in parts if p.is_zip]
    if zips:
        return max(zips, key=lambda p: p.size)
    return max(parts, key=lambda p: p.size)     # largest file-ish part


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Carve the OTA firmware package from a pcap")
    ap.add_argument("pcap", help="classic pcap of the plaintext upload to :16170")
    ap.add_argument("-o", "--out", help="write the firmware package here")
    ap.add_argument("--sha256", help="expected SHA256 (from the manifest) to verify")
    ap.add_argument("--all", action="store_true", help="list every file part found")
    args = ap.parse_args(argv)

    try:
        parts = extract_from_pcap(args.pcap)
    except (NotImplementedError, ValueError) as e:
        print(f"error: {e}")
        return 2
    if not parts:
        print("no HTTP multipart file upload found (wrong capture? encrypted 802.11? "
              "firmware rides :16170 plain HTTP — not the UCP .fwcap)")
        return 1

    if args.all:
        for p in parts:
            print("· " + p.summary())
        print()
    fw = _pick_firmware(parts)
    print("firmware: " + fw.summary())

    if args.sha256:
        ok = fw.sha256.lower() == args.sha256.lower()
        print(f"sha256 {'MATCH ✓' if ok else 'MISMATCH ✗ (expected ' + args.sha256 + ')'}")
    if args.out:
        with open(args.out, "wb") as f:
            f.write(fw.data)
        print(f"wrote {fw.size} B → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
