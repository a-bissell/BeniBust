"""Minimal AVB vbmeta parser (stdlib only).

Wire layout follows Android libavb (network byte order), see:
  - libavb/avb_vbmeta_image.h (AvbVBMetaImageHeader)
  - libavb/avb_descriptor.h (AvbDescriptor: tag, num_bytes_following)
  - libavb/avb_hashtree_descriptor.h / avb_hash_descriptor.h
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

AVB_MAGIC = b"AVB0"
AVB_VBMETA_HEADER_SIZE = 256

AVB_DESCRIPTOR_HEADER_SIZE = 16

AVB_DESCRIPTOR_TAG_HASHTREE = 1
AVB_DESCRIPTOR_TAG_HASH = 2

# Serialized body size after the 16-byte AvbDescriptor header (AvbHashtreeDescriptor w/o parent).
_HASHTREE_FIXED_BODY = (
    4 + 8 + 8 + 8 + 4 + 4 + 4 + 8 + 8 + 32 + 4 + 4 + 4 + 4 + 60
)
# AvbHashDescriptor body after the header.
_HASH_FIXED_BODY = 8 + 32 + 4 + 4 + 4 + 4 + 60


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


def _be64(data: bytes, offset: int) -> int:
    return struct.unpack_from(">Q", data, offset)[0]


def _be32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def _utf8_partition_name(blob: bytes) -> Optional[str]:
    if not blob:
        return None
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parse_hashtree_body(body: bytes) -> Optional[str]:
    if len(body) < _HASHTREE_FIXED_BODY:
        return None
    name_len = _be32(body, 88)
    salt_len = _be32(body, 92)
    root_len = _be32(body, 96)
    var_start = _HASHTREE_FIXED_BODY
    var_total = name_len + salt_len + root_len
    if var_start + var_total > len(body):
        return None
    part = body[var_start : var_start + name_len]
    return _utf8_partition_name(part)


def _parse_hash_body(body: bytes) -> Optional[str]:
    if len(body) < _HASH_FIXED_BODY:
        return None
    name_len = _be32(body, 40)
    salt_len = _be32(body, 44)
    digest_len = _be32(body, 48)
    var_start = _HASH_FIXED_BODY
    var_total = name_len + salt_len + digest_len
    if var_start + var_total > len(body):
        return None
    part = body[var_start : var_start + name_len]
    return _utf8_partition_name(part)


def _parse_descriptor_payload(tag: int, body: bytes) -> AvbDescriptor:
    part: Optional[str] = None
    if tag == AVB_DESCRIPTOR_TAG_HASHTREE:
        part = _parse_hashtree_body(body)
    elif tag == AVB_DESCRIPTOR_TAG_HASH:
        part = _parse_hash_body(body)
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
        auth_size = _be64(blob, 12)
        aux_size = _be64(blob, 20)
        desc_off = _be64(blob, 96)
        desc_size = _be64(blob, 104)
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

    if desc_off > len(aux) or desc_off + desc_size > len(aux):
        return VbmetaParseResult(status="unparseable", detail="descriptor table out of auxiliary bounds")

    table = aux[desc_off : desc_off + desc_size]
    offset = 0
    descriptors: List[AvbDescriptor] = []
    hashtree: List[str] = []
    hashes: List[str] = []

    while offset < len(table):
        if offset + AVB_DESCRIPTOR_HEADER_SIZE > len(table):
            return VbmetaParseResult(status="unparseable", detail="descriptor header truncated")
        try:
            tag = _be64(table, offset)
            nb_following = _be64(table, offset + 8)
        except struct.error:
            return VbmetaParseResult(status="unparseable", detail="descriptor header unpack failed")
        if nb_following % 8 != 0:
            return VbmetaParseResult(status="unparseable", detail="descriptor length not 8-byte aligned")
        total = AVB_DESCRIPTOR_HEADER_SIZE + nb_following
        if offset + total > len(table):
            return VbmetaParseResult(status="unparseable", detail="descriptor extends past table")
        body = table[offset + AVB_DESCRIPTOR_HEADER_SIZE : offset + total]
        desc = _parse_descriptor_payload(tag, body)
        descriptors.append(desc)
        if desc.partition_name:
            if tag == AVB_DESCRIPTOR_TAG_HASHTREE:
                hashtree.append(desc.partition_name)
            elif tag == AVB_DESCRIPTOR_TAG_HASH:
                hashes.append(desc.partition_name)
        offset += total

    if offset != len(table):
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