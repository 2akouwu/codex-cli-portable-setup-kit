"""Reverse Engineering, Protocol Dissection, and Dynamic Instrumentation Toolkit."""

from .pe_parser import PEParser, BinaryParseError
from .disasm import Disassembler, Instruction, pattern_scan, create_patch
from .emulator import MicroEmulator, UnicornEmulator, make_emulator, EmulatorError
from .binary import parse_binary, BinaryInfo, Section
from .backends import backend_report, HAS_CAPSTONE, HAS_UNICORN, HAS_LIEF
from .protocol_parser import ProtobufDissector, TLVDissector, format_hexdump, decode_varint, encode_varint
from .frida_bridge import FridaScriptGenerator
from .verifier import Verifier, Claim, verify_claims, VERIFIED, REFUTED, INCONCLUSIVE
from .agent import ReconstructionAgent, openai_proposer, demo_proposer, binary_facts

__all__ = [
    "PEParser",
    "BinaryParseError",
    "Disassembler",
    "Instruction",
    "pattern_scan",
    "create_patch",
    "MicroEmulator",
    "UnicornEmulator",
    "make_emulator",
    "EmulatorError",
    "parse_binary",
    "BinaryInfo",
    "Section",
    "backend_report",
    "HAS_CAPSTONE",
    "HAS_UNICORN",
    "HAS_LIEF",
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
    "ReconstructionAgent",
    "openai_proposer",
    "demo_proposer",
    "binary_facts",
]
