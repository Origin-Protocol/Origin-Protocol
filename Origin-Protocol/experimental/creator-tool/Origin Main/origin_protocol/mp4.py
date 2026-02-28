from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Tuple

ORIGIN_UUID = "e1b1c6b2-4d0a-4b40-9a1c-5d1d8f0e9c2a"


def _uuid_bytes() -> bytes:
    return bytes.fromhex(ORIGIN_UUID.replace("-", ""))


@dataclass(frozen=True)
class UuidBox:
    payload: bytes


def build_uuid_box(payload: bytes) -> bytes:
    size = 8 + 16 + len(payload)
    if size > 0xFFFFFFFF:
        return struct.pack(">I4sQ16s", 1, b"uuid", size, _uuid_bytes()) + payload
    return struct.pack(">I4s16s", size, b"uuid", _uuid_bytes()) + payload


def _box_bytes(box_type: bytes, payload: bytes) -> bytes:
    size = 8 + len(payload)
    if size > 0xFFFFFFFF:
        return struct.pack(">I4sQ", 1, box_type, size) + payload
    return struct.pack(">I4s", size, box_type) + payload


def _iter_boxes_raw(data: bytes) -> Iterator[Tuple[int, bytes, bytes, bytes]]:
    offset = 0
    size_data = len(data)
    while offset + 8 <= size_data:
        size, box_type = struct.unpack(">I4s", data[offset:offset + 8])
        header_size = 8
        if size == 1:
            if offset + 16 > size_data:
                break
            size = struct.unpack(">Q", data[offset + 8:offset + 16])[0]
            header_size = 16
        elif size == 0:
            size = size_data - offset

        if size < header_size or size == 0:
            break

        payload_start = offset + header_size
        payload_end = offset + size
        if payload_end > size_data:
            break
        raw = data[offset:payload_end]
        payload = data[payload_start:payload_end]
        yield offset, box_type, payload, raw
        if size == 0:
            break
        offset = payload_end


def append_uuid_box(input_path: Path, output_path: Path, payload: bytes) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("rb") as source, output_path.open("wb") as target:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            target.write(chunk)
        target.write(build_uuid_box(payload))
    return output_path


def insert_uuid_box(input_path: Path, output_path: Path, payload: bytes) -> Path:
    data = input_path.read_bytes()
    moov_payload = None
    moov_header_size = 8
    moov_raw = None
    prefix = b""
    suffix = b""
    seen_fragment = False
    for _, box_type, box_payload, raw in _iter_boxes_raw(data):
        if box_type == b"moov":
            moov_payload = box_payload
            moov_raw = raw
            moov_header_size = len(raw) - len(box_payload)
        else:
            if moov_payload is None:
                prefix += raw
            else:
                suffix += raw
        if box_type in {b"moof", b"mfra"}:
            seen_fragment = True

    if moov_payload is None:
        if seen_fragment:
            return append_uuid_box(input_path, output_path, payload)
        return append_uuid_box(input_path, output_path, payload)

    udta_payload: bytes | None = None
    new_moov_children: list[tuple[bytes, bytes]] = []
    for _, child_type, child_payload, raw in _iter_boxes_raw(moov_payload):
        if child_type == b"udta":
            udta_payload = child_payload
        new_moov_children.append((child_type, raw))

    uuid_box = build_uuid_box(payload)
    if udta_payload is None:
        udta_payload = uuid_box
    else:
        meta_payload = None
        meta_version_flags = b"\x00\x00\x00\x00"
        new_udta_children: list[bytes] = []
        for _, udta_child_type, udta_child_payload, udta_raw in _iter_boxes_raw(udta_payload):
            if udta_child_type == b"meta":
                meta_payload = udta_child_payload
            else:
                new_udta_children.append(udta_raw)

        if meta_payload is not None:
            if len(meta_payload) >= 4:
                meta_version_flags = meta_payload[:4]
                meta_children = meta_payload[4:]
            else:
                meta_children = b""
            meta_children += uuid_box
            meta_payload = meta_version_flags + meta_children
            new_udta_children.append(_box_bytes(b"meta", meta_payload))
            udta_payload = b"".join(new_udta_children)
        else:
            udta_payload += uuid_box

    udta_box = _box_bytes(b"udta", udta_payload)
    replaced = False
    for idx, (child_type, raw) in enumerate(new_moov_children):
        if child_type == b"udta":
            new_moov_children[idx] = (b"udta", udta_box)
            replaced = True
            break
    if not replaced:
        new_moov_children.append((b"udta", udta_box))

    moov_payload = b"".join(raw for _, raw in new_moov_children)
    if moov_header_size == 16:
        moov_size = len(moov_payload) + 16
        moov_box = struct.pack(">I4sQ", 1, b"moov", moov_size) + moov_payload
    else:
        moov_box = _box_bytes(b"moov", moov_payload)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if moov_raw is not None:
        output_path.write_bytes(prefix + moov_box + suffix)
    else:
        output_path.write_bytes(prefix + moov_box + suffix)
    return output_path


def extract_uuid_payloads(path: Path) -> list[UuidBox]:
    payloads: list[UuidBox] = []
    with path.open("rb") as handle:
        while True:
            header = handle.read(8)
            if len(header) < 8:
                break
            size, box_type = struct.unpack(">I4s", header)
            if size == 1:
                large_size_bytes = handle.read(8)
                if len(large_size_bytes) < 8:
                    break
                size = struct.unpack(">Q", large_size_bytes)[0]
                header_size = 16
            else:
                header_size = 8

            if size == 0:
                box_data = handle.read()
            else:
                remaining = size - header_size
                if remaining < 0:
                    break
                box_data = handle.read(remaining)

            if box_type == b"uuid":
                if len(box_data) < 16:
                    continue
                if box_data[:16] == _uuid_bytes():
                    payloads.append(UuidBox(payload=box_data[16:]))

            if size == 0:
                break

    return payloads
