"""A minimal, read-only protobuf wire-format reader.

Only what the ONNX scanner needs: walk fields without a schema, decode varints,
length-delimited bytes and nested messages. No protobuf library, so the scanner
does not share a parser with the loaders it inspects, and an unknown field is
skipped rather than being a hard error.
"""
from __future__ import annotations

from collections.abc import Iterator

WIRE_VARINT = 0
WIRE_I64 = 1
WIRE_LEN = 2
WIRE_I32 = 5
__all__ = [
    "WIRE_VARINT", "WIRE_I64", "WIRE_LEN", "WIRE_I32",
    "ProtobufError", "read_varint", "iter_fields", "message_fields", "first_bytes", "text",
]
# Deprecated group wire types (3, 4) are refused: no ONNX message uses them.

MAX_VARINT_BYTES = 10  # a 64-bit varint is at most 10 bytes


class ProtobufError(ValueError):
    pass


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise ProtobufError("varint runs past end of buffer")
        if pos - start >= MAX_VARINT_BYTES:
            raise ProtobufError("varint longer than 10 bytes")
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not byte & 0x80:
            return result, pos
        shift += 7


def iter_fields(data: bytes, allow_truncated: bool = False) -> Iterator[tuple[int, int, object]]:
    """Yield (field_number, wire_type, value) for each field in one message.

    value is an int for varint/I32/I64 fields and a bytes slice for length-delimited
    fields. Raises ProtobufError on malformed input.

    `allow_truncated` is for the one caller that reads a bounded prefix on purpose:
    format detection. A field whose payload runs past the end of a prefix is not
    evidence of a malformed file — the field header is still evidence the field is
    there, which is all a sniffer can ask. Such a field is yielded with value None
    and the walk stops. The default stays strict, because for the scanner, reading
    the whole file, a field running past the end really is malformed.
    """
    pos = 0
    n = len(data)

    def varint(at: int) -> tuple[int, int] | None:
        """A varint, or None where a deliberate prefix read ran out mid-number."""
        try:
            return read_varint(data, at)
        except ProtobufError:
            if allow_truncated:
                return None
            raise

    while pos < n:
        read = varint(pos)
        if read is None:
            return
        key, pos = read
        field_number, wire_type = key >> 3, key & 0x07
        if field_number == 0:
            raise ProtobufError("field number 0 is invalid")
        if wire_type == WIRE_VARINT:
            read = varint(pos)
            if read is None:
                return
            value, pos = read
        elif wire_type == WIRE_LEN:
            read = varint(pos)
            if read is None:
                return
            length, pos = read
            if length > n - pos:
                if allow_truncated:
                    yield field_number, wire_type, None
                    return
                raise ProtobufError("length-delimited field runs past end of buffer")
            value = data[pos:pos + length]
            pos += length
        elif wire_type == WIRE_I64:
            value, pos = int.from_bytes(data[pos:pos + 8], "little"), pos + 8
        elif wire_type == WIRE_I32:
            value, pos = int.from_bytes(data[pos:pos + 4], "little"), pos + 4
        else:
            raise ProtobufError(f"unsupported wire type {wire_type}")
        yield field_number, wire_type, value


def message_fields(data: bytes) -> dict[int, list[object]]:
    """All fields of a message grouped by number. Repeated fields keep every value."""
    fields: dict[int, list[object]] = {}
    for number, _wire, value in iter_fields(data):
        fields.setdefault(number, []).append(value)
    return fields


def first_bytes(fields: dict[int, list[object]], number: int) -> bytes | None:
    values = fields.get(number)
    if not values:
        return None
    value = values[0]
    return value if isinstance(value, (bytes, bytearray)) else None


def text(fields: dict[int, list[object]], number: int) -> str | None:
    raw = first_bytes(fields, number)
    return raw.decode("utf-8", "replace") if raw is not None else None
