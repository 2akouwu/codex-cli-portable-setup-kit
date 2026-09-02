import unittest
import sys
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from protocol_parser import ProtobufDissector, TLVDissector, format_hexdump, decode_varint, encode_varint


class TestProtocolParser(unittest.TestCase):
    def test_varint_encode_decode(self):
        cases = [0, 1, 127, 128, 300, 1000000]
        for val in cases:
            enc = encode_varint(val)
            dec, offset = decode_varint(enc, 0)
            self.assertEqual(dec, val)
            self.assertEqual(offset, len(enc))

    def test_protobuf_dissector(self):
        # Field 1 (varint): 150 -> tag: (1<<3)|0 = 0x08, value: 0x96 0x01
        # Field 2 (string): "test" -> tag: (2<<3)|2 = 0x12, length: 4, "test"
        data = bytes([0x08, 0x96, 0x01, 0x12, 0x04, ord("t"), ord("e"), ord("s"), ord("t")])
        tree = ProtobufDissector.dissect(data)

        self.assertIn("field_1", tree)
        self.assertEqual(tree["field_1"][0]["value"], 150)
        self.assertIn("field_2", tree)
        self.assertEqual(tree["field_2"][0]["value"], "test")

    def test_tlv_dissector(self):
        # Type: 0x01, Length: 0x0003, Value: "ABC"
        # Type: 0x02, Length: 0x0002, Value: "XY"
        data = bytes([0x01, 0x00, 0x03, ord("A"), ord("B"), ord("C"), 0x02, 0x00, 0x02, ord("X"), ord("Y")])
        tlvs = TLVDissector.dissect(data, type_len=1, length_len=2)

        self.assertEqual(len(tlvs), 2)
        self.assertEqual(tlvs[0]["type"], 1)
        self.assertEqual(tlvs[0]["text"], "ABC")
        self.assertEqual(tlvs[1]["type"], 2)
        self.assertEqual(tlvs[1]["text"], "XY")

    def test_hexdump(self):
        dump = format_hexdump(b"Hello, World!", base_address=0x1000)
        self.assertIn("00001000", dump)
        self.assertIn("Hello, World!", dump)


if __name__ == "__main__":
    unittest.main()
