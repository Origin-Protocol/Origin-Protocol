from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ORIGIN_TAG_NAME = b"ORIGIN"


@dataclass(frozen=True)
class OriginTag:
    payload: bytes


def _vint_size(value: int) -> bytes:
    if value < (1 << 7) - 1:
        return bytes([0x80 | value])
    if value < (1 << 14) - 1:
        return bytes([0x40 | (value >> 8), value & 0xFF])
    if value < (1 << 21) - 1:
        return bytes([0x20 | (value >> 16), (value >> 8) & 0xFF, value & 0xFF])
    if value < (1 << 28) - 1:
        return bytes(
            [
                0x10 | (value >> 24),
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            ]
        )
    raise ValueError("Value too large for EBML vint")


def _read_vint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Invalid EBML vint")
    first = data[offset]
    mask = 0x80
    length = 1
    while length <= 8 and not (first & mask):
        mask >>= 1
        length += 1
    if length > 8:
        raise ValueError("Invalid EBML vint")
    value = first & (mask - 1)
    for i in range(1, length):
        if offset + i >= len(data):
            raise ValueError("Invalid EBML vint")
        value = (value << 8) | data[offset + i]
    return value, length


def _read_element_id(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Invalid EBML element id")
    first = data[offset]
    mask = 0x80
    length = 1
    while length <= 4 and not (first & mask):
        mask >>= 1
        length += 1
    if length > 4:
        raise ValueError("Invalid EBML element id")
    element_id = 0
    for i in range(length):
        element_id = (element_id << 8) | data[offset + i]
    return element_id, length


def _iter_elements(data: bytes, offset: int, size: int) -> list[tuple[int, int, int]]:
    elements: list[tuple[int, int, int]] = []
    end = offset + size
    cursor = offset
    while cursor < end:
        try:
            element_id, id_len = _read_element_id(data, cursor)
            cursor += id_len
            value, size_len = _read_vint(data, cursor)
            cursor += size_len
            if value < 0 or cursor + value > end:
                break
            elements.append((element_id, cursor, value))
            cursor += value
        except Exception:
            break
    return elements


def _element(element_id: bytes, payload: bytes) -> bytes:
    return element_id + _vint_size(len(payload)) + payload


def build_origin_tag_element(payload: bytes) -> bytes:
    # SimpleTag
    tag_name = _element(b"\x45\xA3", ORIGIN_TAG_NAME)
    tag_value = _element(b"\x44\x87", payload)
    simple_tag = _element(b"\x67\xC8", tag_name + tag_value)

    # Tag
    tag = _element(b"\x73\x73", simple_tag)

    # Tags
    return _element(b"\x12\x54\xC3\x67", tag)


def append_origin_tag(input_path: Path, output_path: Path, payload: bytes) -> Path:
    data = input_path.read_bytes()
    inserted = False
    segment_id = 0x18538067
    cluster_id = 0x1F43B675
    info_id = 0x1549A966
    tags_element = build_origin_tag_element(payload)

    try:
        cursor = 0
        while cursor < len(data):
            element_id, id_len = _read_element_id(data, cursor)
            cursor += id_len
            size_value, size_len = _read_vint(data, cursor)
            cursor += size_len
            unknown_size = size_value == (1 << (7 * size_len)) - 1
            if element_id == segment_id:
                segment_start = cursor - id_len - size_len
                payload_start = cursor
                payload_end = len(data) if unknown_size else payload_start + size_value
                if payload_end > len(data):
                    break

                segment_payload = data[payload_start:payload_end]
                insert_pos = len(segment_payload)
                info_end = None
                for child_id, child_start, child_size in _iter_elements(segment_payload, 0, len(segment_payload)):
                    if child_id == info_id:
                        info_end = child_start + child_size
                    if child_id == cluster_id:
                        insert_pos = min(insert_pos, child_start)
                        break
                if info_end is not None:
                    insert_pos = max(info_end, 0)

                new_segment_payload = (
                    segment_payload[:insert_pos] + tags_element + segment_payload[insert_pos:]
                )
                if unknown_size:
                    new_data = data[:payload_start] + new_segment_payload + data[payload_end:]
                else:
                    new_size = len(new_segment_payload)
                    new_header = data[segment_start:segment_start + id_len] + _vint_size(new_size)
                    new_data = (
                        data[:segment_start] + new_header + new_segment_payload + data[payload_end:]
                    )
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(new_data)
                inserted = True
                break

            if size_value == 0:
                break
            cursor = cursor + size_value
    except Exception:
        inserted = False

    if inserted:
        return output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("rb") as source, output_path.open("wb") as target:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            target.write(chunk)
        target.write(tags_element)
    return output_path


def _scan_for_origin_tags(data: bytes) -> list[OriginTag]:
    tags: list[OriginTag] = []
    idx = 0
    while idx < len(data):
        name_pos = data.find(b"\x45\xA3", idx)
        if name_pos == -1:
            break
        size_start = name_pos + 2
        if size_start >= len(data):
            break
        try:
            name_size, name_len = _read_vint(data, size_start)
        except Exception:
            idx = name_pos + 2
            continue
        name_start = size_start + name_len
        name_end = name_start + name_size
        if name_end > len(data):
            break
        name = data[name_start:name_end]
        if name != ORIGIN_TAG_NAME:
            idx = name_end
            continue

        search_start = name_end
        value_pos = data.find(b"\x44\x87", search_start)
        if value_pos == -1:
            idx = name_end
            continue
        value_size_start = value_pos + 2
        if value_size_start >= len(data):
            break
        try:
            value_size, value_len = _read_vint(data, value_size_start)
        except Exception:
            idx = value_pos + 2
            continue
        payload_start = value_size_start + value_len
        payload_end = payload_start + value_size
        if payload_end > len(data):
            break
        tags.append(OriginTag(payload=data[payload_start:payload_end]))
        idx = payload_end
    return tags


def extract_origin_payloads(path: Path) -> list[OriginTag]:
    data = path.read_bytes()
    results: list[OriginTag] = []
    try:
        tags_id = 0x1254C367
        tag_id = 0x7373
        simple_tag_id = 0x67C8
        tag_name_id = 0x45A3
        tag_string_id = 0x4487

        for element_id, start, size in _iter_elements(data, 0, len(data)):
            if element_id != tags_id:
                continue
            for tag_element_id, tag_start, tag_size in _iter_elements(data, start, size):
                if tag_element_id != tag_id:
                    continue
                for simple_id, simple_start, simple_size in _iter_elements(data, tag_start, tag_size):
                    if simple_id != simple_tag_id:
                        continue
                    name = None
                    value = None
                    for item_id, item_start, item_size in _iter_elements(data, simple_start, simple_size):
                        if item_id == tag_name_id:
                            name = data[item_start:item_start + item_size]
                        elif item_id == tag_string_id:
                            value = data[item_start:item_start + item_size]
                    if name == ORIGIN_TAG_NAME and value is not None:
                        results.append(OriginTag(payload=value))
    except Exception:
        results = []

    if results:
        return results

    return _scan_for_origin_tags(data)
