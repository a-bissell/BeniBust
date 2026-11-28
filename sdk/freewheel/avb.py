"""Minimal AVB vbmeta parser (stdlib only).

Parses the `AVB0` vbmeta image header and the descriptor table in the auxiliary block.
Used to detect whether `mondo` is covered by dm-verity hashtree metadata before allowing
in-place `mondo.img` patches.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

AVB_MAGIC = b"AVB0"
AVB_VBMETA_HEADER_SIZE = 256

AVB_DESCRIPTOR_TAG_HASHTREE = 1
AVB_DESCRIPTOR_TAG_HASH = 2

# Fixed payload layout matching libavb's packed descriptor structs (`<QQQQQQIQQ` / `<QQQ` + name[32]).
_HASHTREE_NUMERIC = struct.calcsize("<QQQQQQIQQ")
_HASHTREE_NAME_LEN = 32
_HASHTREE_FIXED = _HASHTREE_NUMERIC + _HASHTREE_NAME_LEN
_HASH_NUMERIC = struct.calcsize("<QQQ")
_HASH_NAME_LEN = 32
_HASH_FIXED = _HASH_NUMERIC + _HASH_NAME_LEN


@dataclass(frozen=True)
class AvbDescriptor:
    tag: int
    partition_name: Optional[str]


@dataclass(frozen=True)
class VbmetaParseResult:
    """Outcome of parsing one vbmeta blob."""

    status: str  # ok | unparseable | empty
    hashtree_partitions: Tuple[str, ...] = ()
    hash_partitions: Tuple[str, ...] = ()
    descriptors: Tuple[AvbDescriptor, ...] = ()
    detail: str = ""

    @property
    def mondo_hashtree(self) -> bool:
        return any(_partition_is_mondo(p) for p in self.hashtree_partitions)

    @property
    def mondo_hash(self) -> bool:
        return any(_partition_is_mondo(p) for p in self.hash_partitions)


def _partition_is_mondo(name: str) -> bool:
    return name.strip().lower() == "mondo"


def _read_cstring(blob: bytes, offset: int, limit: int) -> Optional[str]:
    end = blob.find(b"\x00", offset, limit)
    if end < 0:
        if offset >= limit:
            return None
        end = limit
    raw = blob[offset:end]
    if not raw:
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def _partition_name_field(blob: bytes, offset: int) -> Optional[str]:
    if offset + _HASHTREE_NAME_LEN > len(blob):
        return None
    field = blob[offset : offset + _HASHTREE_NAME_LEN]
    return _read_cstring(field, 0, len(field))


def _parse_descriptor_payload(tag: int, payload: bytes) -> AvbDescriptor:
    part: Optional[str] = None
    if tag == AVB_DESCRIPTOR_TAG_HASHTREE:
        if len(payload) >= _HASHTREE_FIXED:
            part = _partition_name_field(payload, _HASHTREE_NUMERIC)
    elif tag == AVB_DESCRIPTOR_TAG_HASH:
        if len(payload) >= _HASH_FIXED:
            part = _partition_name_field(payload, _HASH_NUMERIC)
    return AvbDescriptor(tag=tag, partition_name=part)


def parse_vbmeta(blob: bytes) -> VbmetaParseResult:
    """Parse vbmeta; return `unparseable` on malformed input rather than raising."""
    if not blob:
        return VbmetaParseResult(status="empty", detail="empty vbmeta blob")
    if len(blob) < AVB_VBMETA_HEADER_SIZE:
        return VbmetaParseResult(status="unparseable", detail="truncated vbmeta header")
    if blob[:4] != AVB_MAGIC:
        return VbmetaParseResult(status="unparseable", detail=f"bad magic {blob[:4]!r}")
    try:
        auth_size, aux_size = struct.unpack_from("<QQ", blob, 12)
        desc_off, desc_size = struct.unpack_from("<II", blob, 64)
    except struct.error:
        return VbmetaParseResult(status="unparseable", detail="header struct unpack failed")

    aux_start = AVB_VBMETA_HEADER_SIZE + auth_size
    if aux_size == 0:
        return VbmetaParseResult(status="ok", detail="no auxiliary block")

    if aux_start + aux_size > len(blob):
        return VbmetaParseResult(status="unparseable", detail="auxiliary block extends past EOF")

    aux = blob[aux_start : aux_start + aux_size]
    if desc_size == 0:
        return VbmetaParseResult(status="ok", detail="descriptor table empty")

    if desc_off + desc_size > len(aux):
        return VbmetaParseResult(status="unparseable", detail="descriptor table out of auxiliary bounds")

    table = aux[desc_off : desc_off + desc_size]
    offset = 0
    descriptors: List[AvbDescriptor] = []
    hashtree: List[str] = []
    hashes: List[str] = []

    while offset + 16 <= len(table):
        try:
            tag, num_bytes = struct.unpack_from("<QQ", table, offset)
        except struct.error:
            return VbmetaParseResult(status="unparseable", detail="descriptor header truncated")
        if num_bytes < 16:
            return VbmetaParseResult(status="unparseable", detail=f"descriptor size {num_bytes} < 16")
        if offset + num_bytes > len(table):
            return VbmetaParseResult(status="unparseable", detail="descriptor extends past table")
        payload = table[offset + 16 : offset + num_bytes]
        desc = _parse_descriptor_payload(tag, payload)
        descriptors.append(desc)
        if desc.partition_name:
            if tag == AVB_DESCRIPTOR_TAG_HASHTREE:
                hashtree.append(desc.partition_name)
            elif tag == AVB_DESCRIPTOR_TAG_HASH:
                hashes.append(desc.partition_name)
        offset += num_bytes

    if offset != len(table) and offset < len(table):
        # Trailing garbage after the last aligned descriptor is unparseable.
        return VbmetaParseResult(status="unparseable", detail="trailing bytes in descriptor table")

    return VbmetaParseResult(
        status="ok",
        hashtree_partitions=tuple(hashtree),
        hash_partitions=tuple(hashes),
        descriptors=tuple(descriptors),
    )


@dataclass
class MondoVerityEvidence:
    """Combined dm-verity signals for `/md` / `mondo.img`."""

    sources: List[str] = field(default_factory=list)
    vbmeta: Optional[VbmetaParseResult] = None

    @property
    def covered(self) -> bool:
        return bool(self.sources)

    def summary(self) -> str:
        return "; ".join(self.sources) if self.sources else "none"

    def format_report_line(self) -> str:
        vb = self.vbmeta
        vb_part = "vbmeta unparseable"
        if vb is not None:
            if vb.status == "ok":
                parts = []
                if vb.hashtree_partitions:
                    parts.append("hashtree=" + ",".join(vb.hashtree_partitions))
                if vb.hash_partitions:
                    parts.append("hash=" + ",".join(vb.hash_partitions))
                vb_part = "vbmeta ok (" + (", ".join(parts) if parts else "no hash descriptors") + ")"
            else:
                vb_part = f"vbmeta {vb.status} ({vb.detail})"
        return f"mondo dm-verity evidence: {self.summary()} | {vb_part}"