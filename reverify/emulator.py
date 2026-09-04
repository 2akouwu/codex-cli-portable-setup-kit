"""Micro-architecture CPU and register state emulator for isolated algorithm execution."""

from typing import Dict, Any, List, Optional


class EmulatorError(Exception):
    pass


class MicroEmulator:
    """Lightweight pure-Python CPU emulator for tracing and algorithm verification."""

    def __init__(self, arch: str = "x86_64", stack_base: int = 0x10000, stack_size: int = 0x10000):
        self.arch = arch.lower()
        self.is_64bit = "64" in self.arch or "amd64" in self.arch
        self.registers: Dict[str, int] = {}
        self.memory: bytearray = bytearray(0x100000)  # 1MB virtual memory space
        self.mem_base = 0x1000
        self.stack_base = stack_base
        self.stack_size = stack_size
        self.steps_executed = 0
        self.max_steps = 10000
        self.halted = False
        self.trace_log: List[str] = []
        self._init_registers()

    def _init_registers(self) -> None:
        regs = [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags"
        ] if self.is_64bit else [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags"
        ]
        for r in regs:
            self.registers[r] = 0
        sp_name = "rsp" if self.is_64bit else "esp"
        self.registers[sp_name] = self.stack_base + self.stack_size - 0x100

    def reg_read(self, name: str) -> int:
        return self.registers.get(name.lower(), 0)

    def reg_write(self, name: str, val: int) -> None:
        mask = 0xFFFFFFFFFFFFFFFF if self.is_64bit else 0xFFFFFFFF
        self.registers[name.lower()] = val & mask

    def mem_write(self, address: int, data: bytes) -> None:
        offset = address - self.mem_base
        if 0 <= offset and offset + len(data) <= len(self.memory):
            self.memory[offset : offset + len(data)] = data
        else:
            raise EmulatorError(f"Memory write out of bounds: 0x{address:X}")

    def mem_read(self, address: int, size: int) -> bytes:
        offset = address - self.mem_base
        if 0 <= offset and offset + size <= len(self.memory):
            return bytes(self.memory[offset : offset + size])
        return bytes(size)

    def load_code(self, code: bytes, base_address: int = 0x1000) -> None:
        self.mem_base = min(base_address, self.stack_base)
        self.mem_write(base_address, code)
        ip_name = "rip" if self.is_64bit else "eip"
        self.reg_write(ip_name, base_address)

    def push(self, val: int) -> None:
        sp_name = "rsp" if self.is_64bit else "esp"
        size = 8 if self.is_64bit else 4
        sp = self.reg_read(sp_name) - size
        self.reg_write(sp_name, sp)
        self.mem_write(sp, val.to_bytes(size, "little"))

    def pop(self) -> int:
        sp_name = "rsp" if self.is_64bit else "esp"
        size = 8 if self.is_64bit else 4
        sp = self.reg_read(sp_name)
        val = int.from_bytes(self.mem_read(sp, size), "little")
        self.reg_write(sp_name, sp + size)
        return val

    def step(self) -> bool:
        if self.halted:
            return False

        ip_name = "rip" if self.is_64bit else "eip"
        ip = self.reg_read(ip_name)
        raw = self.mem_read(ip, 16)
        if not raw or raw[0] == 0:
            self.halted = True
            return False

        b0 = raw[0]

        # NOP
        if b0 == 0x90:
            self.reg_write(ip_name, ip + 1)
            self.trace_log.append(f"0x{ip:X}: NOP")
        # RET / INT3 -> Halt
        elif b0 in (0xC3, 0xCC):
            self.reg_write(ip_name, ip + 1)
            self.trace_log.append(f"0x{ip:X}: RET/HALT")
            self.halted = True
            self.steps_executed += 1
            return False
        # PUSH r64/r32 (0x50 - 0x57)
        elif 0x50 <= b0 <= 0x57:
            regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] if self.is_64bit else ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            r = regs[b0 - 0x50]
            val = self.reg_read(r)
            self.push(val)
            self.reg_write(ip_name, ip + 1)
            self.trace_log.append(f"0x{ip:X}: PUSH {r} (0x{val:X})")
        # POP r64/r32 (0x58 - 0x5F)
        elif 0x58 <= b0 <= 0x5F:
            regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] if self.is_64bit else ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            r = regs[b0 - 0x58]
            val = self.pop()
            self.reg_write(r, val)
            self.reg_write(ip_name, ip + 1)
            self.trace_log.append(f"0x{ip:X}: POP {r} -> 0x{val:X}")
        # MOV r32/r64, imm (0xB8 - 0xBF)
        elif 0xB8 <= b0 <= 0xBF:
            regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] if self.is_64bit else ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            r = regs[b0 - 0xB8]
            imm = int.from_bytes(raw[1:5], "little")
            self.reg_write(r, imm)
            self.reg_write(ip_name, ip + 5)
            self.trace_log.append(f"0x{ip:X}: MOV {r}, 0x{imm:X}")
        # XOR reg, reg (0x31)
        elif b0 == 0x31 and len(raw) >= 2:
            modrm = raw[1]
            regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] if self.is_64bit else ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            src = regs[(modrm >> 3) & 7]
            dst = regs[modrm & 7]
            res = self.reg_read(dst) ^ self.reg_read(src)
            self.reg_write(dst, res)
            self.reg_write(ip_name, ip + 2)
            self.trace_log.append(f"0x{ip:X}: XOR {dst}, {src} -> 0x{res:X}")
        # ADD reg, reg (0x01)
        elif b0 == 0x01 and len(raw) >= 2:
            modrm = raw[1]
            regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] if self.is_64bit else ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            src = regs[(modrm >> 3) & 7]
            dst = regs[modrm & 7]
            res = self.reg_read(dst) + self.reg_read(src)
            self.reg_write(dst, res)
            self.reg_write(ip_name, ip + 2)
            self.trace_log.append(f"0x{ip:X}: ADD {dst}, {src} -> 0x{res:X}")
        else:
            self.reg_write(ip_name, ip + 1)
            self.trace_log.append(f"0x{ip:X}: UNKNOWN (0x{b0:02X})")

        self.steps_executed += 1
        if self.steps_executed >= self.max_steps:
            self.halted = True
            return False
        return True

    def run(self, max_steps: int = 1000) -> Dict[str, Any]:
        self.max_steps = max_steps
        while not self.halted and self.steps_executed < self.max_steps:
            try:
                if not self.step():
                    break
            except EmulatorError as exc:
                # Wild memory access from hostile/garbage code: fault and halt,
                # never propagate. (Unicorn does the same with UcError.)
                self.trace_log.append(f"fault: {exc}")
                self.halted = True
                break
        return self.dump_state()

    def dump_state(self) -> Dict[str, Any]:
        return {
            "registers": {k: hex(v) for k, v in self.registers.items()},
            "steps_executed": self.steps_executed,
            "halted": self.halted,
            "trace_log": self.trace_log[-20:],
            "backend": "pure-python",
        }


# ---------------------------------------------------------------------------
# Unicorn backend: real CPU emulation for x86 / x86_64 / arm / arm64.
# ---------------------------------------------------------------------------

try:
    from .backends import HAS_UNICORN
except ImportError:  # flat import
    from backends import HAS_UNICORN

_PAGE = 0x1000


def _page_floor(x: int) -> int:
    return x & ~(_PAGE - 1)


def _page_ceil(x: int) -> int:
    return (x + _PAGE - 1) & ~(_PAGE - 1)


class UnicornEmulator:
    """Same interface as :class:`MicroEmulator`, backed by Unicorn Engine.

    Executes every instruction of the architecture instead of a handful, and
    supports x86, x86_64, arm and arm64. A ``ret`` at top level lands on an exit
    sentinel and halts cleanly; falling off the end of the loaded code halts too.
    """

    EXIT = 0xDEAD0000

    _DUMP = {
        "x86_64": ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                   "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"],
        "x86": ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags"],
        "arm64": [f"x{i}" for i in range(31)] + ["sp", "pc"],
        "arm": [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"],
    }

    def __init__(self, arch: str = "x86_64", stack_base: int = 0x10000, stack_size: int = 0x10000):
        if not HAS_UNICORN:
            raise EmulatorError("unicorn is not installed: pip install unicorn")
        import unicorn
        from unicorn import x86_const, arm_const, arm64_const

        a = arch.lower()
        if "64" in a and ("x86" in a or "amd" in a or a in ("x64",)):
            self.norm, uc_arch, uc_mode, self._consts, self._prefix = "x86_64", unicorn.UC_ARCH_X86, unicorn.UC_MODE_64, x86_const, "X86"
            self._pc, self._sp, self.bits = "rip", "rsp", 64
        elif "arm64" in a or "aarch64" in a:
            self.norm, uc_arch, uc_mode, self._consts, self._prefix = "arm64", unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM, arm64_const, "ARM64"
            self._pc, self._sp, self.bits = "pc", "sp", 64
        elif "arm" in a:
            self.norm, uc_arch, uc_mode, self._consts, self._prefix = "arm", unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM, arm_const, "ARM"
            self._pc, self._sp, self.bits = "pc", "sp", 32
        else:
            self.norm, uc_arch, uc_mode, self._consts, self._prefix = "x86", unicorn.UC_ARCH_X86, unicorn.UC_MODE_32, x86_const, "X86"
            self._pc, self._sp, self.bits = "eip", "esp", 32

        self.arch = self.norm
        self.is_64bit = self.bits == 64
        self._uc = unicorn
        self.mu = unicorn.Uc(uc_arch, uc_mode)
        self.stack_base, self.stack_size = stack_base, stack_size
        self.mem_base = 0x1000
        self.code_end = 0x1000
        self.steps_executed = 0
        self.max_steps = 10000
        self.halted = False
        self.trace_log: List[str] = []
        self._mapped: List[tuple] = []

        self._map(stack_base, stack_size)
        self._map(self.EXIT, _PAGE)
        self.reg_write(self._sp, stack_base + stack_size - 0x100)
        # Make a top-level return halt cleanly.
        if self.norm in ("x86", "x86_64"):
            self.push(self.EXIT)
        elif self.norm == "arm64":
            self.reg_write("x30", self.EXIT)
        else:
            self.reg_write("lr", self.EXIT)
        self.mu.hook_add(unicorn.UC_HOOK_CODE, self._hook_code)

    # -- memory -------------------------------------------------------------

    def _is_mapped(self, addr: int, size: int) -> bool:
        return any(lo <= addr and addr + size <= hi for lo, hi in self._mapped)

    def _map(self, addr: int, size: int) -> None:
        lo, hi = _page_floor(addr), _page_ceil(addr + size)
        if self._is_mapped(lo, hi - lo):
            return
        # map only the uncovered span (simple approach: map whole span if untouched)
        try:
            self.mu.mem_map(lo, hi - lo)
            self._mapped.append((lo, hi))
        except self._uc.UcError:
            # overlaps an existing mapping; extend page by page
            for page in range(lo, hi, _PAGE):
                if not self._is_mapped(page, _PAGE):
                    self.mu.mem_map(page, _PAGE)
                    self._mapped.append((page, page + _PAGE))

    def mem_write(self, address: int, data: bytes) -> None:
        self._map(address, len(data))
        self.mu.mem_write(address, bytes(data))

    def mem_read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.mu.mem_read(address, size))
        except self._uc.UcError:
            return bytes(size)

    def load_code(self, code: bytes, base_address: int = 0x1000) -> None:
        self.mem_base = base_address
        self.code_end = base_address + len(code)
        self.mem_write(base_address, code)
        self.reg_write(self._pc, base_address)

    # -- registers ----------------------------------------------------------

    def _reg(self, name: str) -> int:
        const = getattr(self._consts, f"UC_{self._prefix}_REG_{name.upper()}", None)
        if const is None:
            raise EmulatorError(f"unknown register '{name}' for {self.norm}")
        return const

    def reg_read(self, name: str) -> int:
        try:
            return int(self.mu.reg_read(self._reg(name)))
        except EmulatorError:
            return 0

    def reg_write(self, name: str, val: int) -> None:
        mask = (1 << self.bits) - 1
        self.mu.reg_write(self._reg(name), val & mask)

    def push(self, val: int) -> None:
        size = self.bits // 8
        sp = self.reg_read(self._sp) - size
        self.reg_write(self._sp, sp)
        self.mem_write(sp, val.to_bytes(size, "little"))

    def pop(self) -> int:
        size = self.bits // 8
        sp = self.reg_read(self._sp)
        val = int.from_bytes(self.mem_read(sp, size), "little")
        self.reg_write(self._sp, sp + size)
        return val

    # -- execution ----------------------------------------------------------

    def _hook_code(self, uc, address, size, user_data):
        if address == self.EXIT or address >= self.code_end or address < self.mem_base:
            self.halted = True
            uc.emu_stop()
            return
        if self.steps_executed >= self.max_steps:
            self.halted = True
            uc.emu_stop()
            return
        self.steps_executed += 1
        if len(self.trace_log) < 200:
            self.trace_log.append(f"0x{address:X}")

    def step(self) -> bool:
        if self.halted:
            return False
        before = self.steps_executed
        pc = self.reg_read(self._pc)
        try:
            self.mu.emu_start(pc, self.code_end, count=1)
        except self._uc.UcError as exc:
            self.trace_log.append(f"fault: {exc}")
            self.halted = True
            return False
        return self.steps_executed > before and not self.halted

    def run(self, max_steps: int = 1000) -> Dict[str, Any]:
        self.max_steps = max_steps
        pc = self.reg_read(self._pc)
        try:
            self.mu.emu_start(pc, self.code_end, count=max_steps)
        except self._uc.UcError as exc:
            self.trace_log.append(f"fault: {exc}")
        self.halted = True
        return self.dump_state()

    def dump_state(self) -> Dict[str, Any]:
        regs = {}
        for name in self._DUMP.get(self.norm, []):
            try:
                regs[name] = hex(self.reg_read(name))
            except Exception:
                pass
        return {
            "registers": regs,
            "steps_executed": self.steps_executed,
            "halted": self.halted,
            "trace_log": self.trace_log[-20:],
            "backend": "unicorn",
        }


def make_emulator(arch: str = "x86_64", prefer: str = "auto", **kwargs):
    """Best available emulator: Unicorn when installed, else the pure micro-emulator.

    ``prefer``: ``"auto"``, ``"unicorn"`` (require it) or ``"pure"``.
    """
    if prefer == "unicorn" and not HAS_UNICORN:
        raise EmulatorError("unicorn backend requested but not installed: pip install unicorn")
    if prefer in ("auto", "unicorn") and HAS_UNICORN:
        return UnicornEmulator(arch=arch, **kwargs)
    a = str(arch).lower()
    if any(tag in a for tag in ("arm", "aarch", "mips", "ppc", "powerpc", "riscv", "sparc")):
        # never run non-x86 code through the x86-only micro-emulator: that would
        # let a wrong claim verify against a meaningless execution
        raise EmulatorError(
            f"'{arch}' emulation needs unicorn (the pure-Python micro-emulator is x86/x64 only): "
            'pip install "reverify[unicorn]"'
        )
    return MicroEmulator(arch=arch, **kwargs)
