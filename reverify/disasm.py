"""Disassembly, signature scanning, and binary patching engine."""

import re
from typing import Dict, Any, List, Optional, Tuple


class Instruction:
    def __init__(self, address: int, size: int, mnemonic: str, op_str: str, raw_bytes: bytes):
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = raw_bytes

    def __repr__(self) -> str:
        hex_bytes = self.bytes.hex()
        return f"0x{self.address:08X}:  {hex_bytes:<16}  {self.mnemonic:<8} {self.op_str}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "size": self.size,
            "bytes": self.bytes.hex(),
            "mnemonic": self.mnemonic,
            "op_str": self.op_str,
        }


class Disassembler:
    """Disassembler supporting pure-Python x86/x64 decoding with Capstone auto-switch."""

    def __init__(self, arch: str = "x86_64"):
        self.arch = arch.lower()
        self._capstone_cs = None
        self._init_capstone()

    def _init_capstone(self) -> None:
        try:
            import capstone
            if "64" in self.arch or "x64" in self.arch or "amd64" in self.arch:
                self._capstone_cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            elif "arm64" in self.arch or "aarch64" in self.arch:
                self._capstone_cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            elif "arm" in self.arch:
                self._capstone_cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            else:
                self._capstone_cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        except ImportError:
            self._capstone_cs = None

    def disassemble(self, code: bytes, base_address: int = 0x1000) -> List[Instruction]:
        if self._capstone_cs is not None:
            instructions = []
            for ins in self._capstone_cs.disasm(code, base_address):
                instructions.append(
                    Instruction(ins.address, ins.size, ins.mnemonic, ins.op_str, bytes(ins.bytes))
                )
            return instructions
        return self._disassemble_pure_python(code, base_address)

    def _disassemble_pure_python(self, code: bytes, base_address: int) -> List[Instruction]:
        """Pure-Python basic x86/x64 instruction decoder."""
        instructions: List[Instruction] = []
        offset = 0
        addr = base_address
        length = len(code)

        reg32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
        reg64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

        while offset < length:
            b0 = code[offset]
            rex_w = False

            # Check REX prefix in 64-bit mode (0x40 - 0x4F)
            if ("64" in self.arch or "amd64" in self.arch) and (0x40 <= b0 <= 0x4F) and offset + 1 < length:
                rex_w = bool(b0 & 0x08)
                offset += 1
                b0 = code[offset]

            regs = reg64 if rex_w else reg32

            # NOP
            if b0 == 0x90:
                instructions.append(Instruction(addr, 1, "nop", "", bytes([b0])))
                offset += 1
                addr += 1
            # INT 3 (Breakpoint)
            elif b0 == 0xCC:
                instructions.append(Instruction(addr, 1, "int3", "", bytes([b0])))
                offset += 1
                addr += 1
            # RET
            elif b0 == 0xC3:
                instructions.append(Instruction(addr, 1, "ret", "", bytes([b0])))
                offset += 1
                addr += 1
            # RET imm16
            elif b0 == 0xC2 and offset + 2 < length:
                imm = int.from_bytes(code[offset + 1 : offset + 3], "little")
                instructions.append(Instruction(addr, 3, "ret", hex(imm), code[offset : offset + 3]))
                offset += 3
                addr += 3
            # PUSH r32/r64 (0x50 - 0x57)
            elif 0x50 <= b0 <= 0x57:
                reg = regs[b0 - 0x50]
                instructions.append(Instruction(addr, 1, "push", reg, bytes([b0])))
                offset += 1
                addr += 1
            # POP r32/r64 (0x58 - 0x5F)
            elif 0x58 <= b0 <= 0x5F:
                reg = regs[b0 - 0x58]
                instructions.append(Instruction(addr, 1, "pop", reg, bytes([b0])))
                offset += 1
                addr += 1
            # PUSH imm32
            elif b0 == 0x68 and offset + 4 < length:
                imm = int.from_bytes(code[offset + 1 : offset + 5], "little", signed=True)
                instructions.append(Instruction(addr, 5, "push", hex(imm), code[offset : offset + 5]))
                offset += 5
                addr += 5
            # PUSH imm8
            elif b0 == 0x6A and offset + 1 < length:
                imm = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
                instructions.append(Instruction(addr, 2, "push", hex(imm), code[offset : offset + 2]))
                offset += 2
                addr += 2
            # MOV r32/r64, imm32/imm64 (0xB8 - 0xBF)
            elif 0xB8 <= b0 <= 0xBF:
                reg = regs[b0 - 0xB8]
                imm_len = 8 if rex_w else 4
                if offset + imm_len < length:
                    imm = int.from_bytes(code[offset + 1 : offset + 1 + imm_len], "little")
                    raw = code[offset : offset + 1 + imm_len]
                    instructions.append(Instruction(addr, len(raw), "mov", f"{reg}, {hex(imm)}", raw))
                    offset += len(raw)
                    addr += len(raw)
                else:
                    offset += 1
                    addr += 1
            # XOR reg, reg (0x31 / 0x33)
            elif b0 in (0x31, 0x33) and offset + 1 < length:
                modrm = code[offset + 1]
                src = regs[(modrm >> 3) & 7]
                dst = regs[modrm & 7]
                raw = code[offset : offset + 2]
                instructions.append(Instruction(addr, 2, "xor", f"{dst}, {src}", raw))
                offset += 2
                addr += 2
            # ADD reg, reg (0x01 / 0x03)
            elif b0 in (0x01, 0x03) and offset + 1 < length:
                modrm = code[offset + 1]
                src = regs[(modrm >> 3) & 7]
                dst = regs[modrm & 7]
                raw = code[offset : offset + 2]
                instructions.append(Instruction(addr, 2, "add", f"{dst}, {src}", raw))
                offset += 2
                addr += 2
            # SUB reg, reg (0x29 / 0x2B)
            elif b0 in (0x29, 0x2B) and offset + 1 < length:
                modrm = code[offset + 1]
                src = regs[(modrm >> 3) & 7]
                dst = regs[modrm & 7]
                raw = code[offset : offset + 2]
                instructions.append(Instruction(addr, 2, "sub", f"{dst}, {src}", raw))
                offset += 2
                addr += 2
            # JMP rel8 (0xEB)
            elif b0 == 0xEB and offset + 1 < length:
                rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
                target = addr + 2 + rel
                instructions.append(Instruction(addr, 2, "jmp", hex(target), code[offset : offset + 2]))
                offset += 2
                addr += 2
            # JMP rel32 (0xE9)
            elif b0 == 0xE9 and offset + 4 < length:
                rel = int.from_bytes(code[offset + 1 : offset + 5], "little", signed=True)
                target = addr + 5 + rel
                instructions.append(Instruction(addr, 5, "jmp", hex(target), code[offset : offset + 5]))
                offset += 5
                addr += 5
            # CALL rel32 (0xE8)
            elif b0 == 0xE8 and offset + 4 < length:
                rel = int.from_bytes(code[offset + 1 : offset + 5], "little", signed=True)
                target = addr + 5 + rel
                instructions.append(Instruction(addr, 5, "call", hex(target), code[offset : offset + 5]))
                offset += 5
                addr += 5
            # Jcc rel8 (0x70 - 0x7F)
            elif 0x70 <= b0 <= 0x7F and offset + 1 < length:
                jcc_names = ["jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "jnbe", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]
                jname = jcc_names[b0 - 0x70]
                rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
                target = addr + 2 + rel
                instructions.append(Instruction(addr, 2, jname, hex(target), code[offset : offset + 2]))
                offset += 2
                addr += 2
            # Default / unknown byte
            else:
                instructions.append(Instruction(addr, 1, "db", hex(b0), bytes([b0])))
                offset += 1
                addr += 1

        return instructions


def pattern_scan(data: bytes, pattern: str) -> List[int]:
    """Scan data for a hex pattern with wildcards (e.g. '48 89 5c 24 ?? 55')."""
    tokens = pattern.strip().split()
    regex_parts = []
    for t in tokens:
        if t in ("?", "??"):
            regex_parts.append(b".")
        else:
            byte_val = int(t, 16)
            regex_parts.append(re.escape(bytes([byte_val])))

    regex = b"".join(regex_parts)
    matches = [m.start() for m in re.finditer(regex, data, re.DOTALL)]
    return matches


def create_patch(original: bytes, patched: bytes, base_address: int = 0) -> List[Dict[str, Any]]:
    """Compare original and patched byte arrays and return diff offsets and values."""
    if len(original) != len(patched):
        raise ValueError("Original and patched data must be the same length")

    patches = []
    i = 0
    while i < len(original):
        if original[i] != patched[i]:
            start = i
            while i < len(original) and original[i] != patched[i]:
                i += 1
            patches.append({
                "offset": hex(start),
                "address": hex(base_address + start),
                "length": i - start,
                "original_bytes": original[start:i].hex(),
                "patched_bytes": patched[start:i].hex(),
            })
        else:
            i += 1
    return patches
