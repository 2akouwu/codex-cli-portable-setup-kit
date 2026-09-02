"""Reverse Engineering, Protocol Dissection, and Dynamic Instrumentation Toolkit."""

from .pe_parser import PEParser, BinaryParseError
from .disasm import Disassembler, Instruction, pattern_scan, create_patch
from .emulator import MicroEmulator, EmulatorError
from .protocol_parser import ProtobufDissector, TLVDissector, format_hexdump, decode_varint, encode_varint
from .frida_bridge import FridaScriptGenerator
from .verifier import Verifier, Claim, verify_claims, VERIFIED, REFUTED, INCONCLUSIVE

__all__ = [
    "PEParser",
    "BinaryParseError",
    "Disassembler",
    "Instruction",
    "pattern_scan",
    "create_patch",
    "MicroEmulator",
    "EmulatorError",
    "ProtobufDissector",
    "TLVDissector",
    "format_hexdump",
    "decode_varint",
    "encode_varint",
    "FridaScriptGenerator",
    "Verifier",
    "Claim",
    "verify_claims",
    "VERIFIED",
    "REFUTED",
    "INCONCLUSIVE",
]
