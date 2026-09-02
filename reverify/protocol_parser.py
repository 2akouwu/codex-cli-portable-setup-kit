"""Protocol and binary serialization format dissector (Protobuf, TLV, and Binary Frames)."""

import struct
from typing import Dict, Any, List, Tuple, Union


class ProtocolParseError(Exception):
    pass


def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode a LEB128/Protobuf varint. Returns (value, new_offset)."""
    val = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, offset
        shift += 7
        if shift > 64:
            raise ProtocolParseError("Varint overflow")
    raise ProtocolParseError("Truncated varint data")


def encode_varint(val: int) -> bytes:
    """Encode an integer as a Protobuf varint."""
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


class ProtobufDissector:
    """Dissect arbitrary raw Protobuf payloads without .proto schema."""

    WIRE_VARINT = 0
    WIRE_FIXED64 = 1
    WIRE_LENGTH_DELIMITED = 2
    WIRE_START_GROUP = 3
    WIRE_END_GROUP = 4
    WIRE_FIXED32 = 5

    @classmethod
    def dissect(cls, data: bytes) -> Dict[str, Any]:
        result: Dict[str, List[Any]] = {}
        offset = 0
        length = len(data)

        while offset < length:
            try:
                tag, offset = decode_varint(data, offset)
            except ProtocolParseError:
                break

            field_number = tag >> 3
            wire_type = tag & 0x07

            if field_number == 0:
                break

            key = f"field_{field_number}"
            if key not in result:
                result[key] = []

            if wire_type == cls.WIRE_VARINT:
                val, offset = decode_varint(data, offset)
                result[key].append({"type": "varint", "value": val})
            elif wire_type == cls.WIRE_FIXED64:
                if offset + 8 > length:
                    break
                (val,) = struct.unpack_from("<Q", data, offset)
                offset += 8
                result[key].append({"type": "fixed64", "value": hex(val), "dec": val})
            elif wire_type == cls.WIRE_LENGTH_DELIMITED:
                field_len, offset = decode_varint(data, offset)
                if offset + field_len > length:
                    break
                raw_bytes = data[offset : offset + field_len]
                offset += field_len

                # First try clean utf-8 printable text
                is_text = False
                try:
                    text = raw_bytes.decode("utf-8")
                    if len(text) > 0 and all(c.isprintable() or c in "\r\n\t" for c in text):
                        result[key].append({"type": "string", "value": text})
                        is_text = True
                except UnicodeDecodeError:
                    pass

                if not is_text:
                    # Try parsing as nested protobuf
                    is_nested = False
                    try:
                        nested = cls.dissect(raw_bytes)
                        if nested and len(nested) > 0:
                            result[key].append({"type": "nested_message", "fields": nested})
                            is_nested = True
                    except Exception:
                        pass

                    if not is_nested:
                        result[key].append({"type": "bytes", "hex": raw_bytes.hex(), "length": len(raw_bytes)})
            elif wire_type == cls.WIRE_FIXED32:
                if offset + 4 > length:
                    break
                (val,) = struct.unpack_from("<I", data, offset)
                offset += 4
                result[key].append({"type": "fixed32", "value": hex(val), "dec": val})
            else:
                break

        return result


class TLVDissector:
    """Type-Length-Value packet dissector."""

    @staticmethod
    def dissect(data: bytes, type_len: int = 1, length_len: int = 2) -> List[Dict[str, Any]]:
        results = []
        offset = 0
        total = len(data)

        while offset + type_len + length_len <= total:
            if type_len == 1:
                t_val = data[offset]
            elif type_len == 2:
                (t_val,) = struct.unpack_from(">H", data, offset)
            else:
                (t_val,) = struct.unpack_from(">I", data, offset)
            offset += type_len

            if length_len == 1:
                l_val = data[offset]
            elif length_len == 2:
                (l_val,) = struct.unpack_from(">H", data, offset)
            else:
                (l_val,) = struct.unpack_from(">I", data, offset)
            offset += length_len

            if offset + l_val > total:
                break

            val_bytes = data[offset : offset + l_val]
            offset += l_val

            results.append({
                "type": t_val,
                "length": l_val,
                "hex": val_bytes.hex(),
                "text": val_bytes.decode("latin1", errors="replace"),
            })

        return results


def format_hexdump(data: bytes, base_address: int = 0) -> str:
    """Format bytes as a standard hexadecimal and ASCII dump."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{base_address + i:08X}  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)
