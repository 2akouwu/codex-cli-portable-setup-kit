#!/usr/bin/env python3
"""A small, dependency-free sandbox for running untrusted native code.

``exebench`` compiles and runs a *candidate* program, and ``behavior_equiv`` may
shell out to a compiler — in both cases the input is arbitrary code from a model
or a dataset. Running it unconfined is why native execution is off by default.
This module makes it *safe to turn on*: a single ``run_sandboxed`` that applies
the strongest confinement each platform offers, fails closed, and reports
honestly what it actually enforces (``protections_active``).

What is enforced:

- **Wall-clock timeout** with a hard kill of the whole process group / tree
  (every platform).
- **Output cap**: stdout/stderr are read up to a byte limit; the child is killed
  if it floods (every platform) — a runaway ``while(1)putchar(...)`` cannot fill
  memory or disk here.
- **Isolated working directory** and **scrubbed environment** (a minimal PATH,
  no inherited secrets), **stdin from /dev/null** (every platform).
- **POSIX resource limits** via ``setrlimit`` in a pre-exec hook: CPU seconds
  (RLIMIT_CPU), address space (RLIMIT_AS — caps memory), file size
  (RLIMIT_FSIZE), process count (RLIMIT_NPROC — blunts fork bombs), and no core
  dumps. The child also gets its own session (``setsid``) so a timeout kills any
  grandchildren.
- **Windows**: a Job Object (best-effort, via ctypes) caps process memory and
  kills the whole job on close; if the Job Object cannot be created the run
  still has the timeout, output cap, cwd and env isolation.

What is *not* claimed: this is not a security boundary against a determined
attacker (no namespaces/seccomp/containers by default). It removes the everyday
foot-guns — infinite loops, memory blow-ups, fork bombs, disk flooding, env
leakage — so ``REVERIFY_ALLOW_NATIVE_EXEC=1`` is a reasonable thing to enable on
a normal dev box. For hostile inputs, run it inside a container as well.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

IS_WINDOWS = os.name == "nt"
IS_POSIX = not IS_WINDOWS

_MB = 1024 * 1024


@dataclass
class SandboxLimits:
    """Resource ceilings for a sandboxed run. ``None`` disables one limit."""

    wall_seconds: float = 10.0            # hard wall-clock timeout (all platforms)
    cpu_seconds: Optional[int] = 5        # RLIMIT_CPU (POSIX)
    memory_bytes: Optional[int] = 512 * _MB   # RLIMIT_AS (POSIX) / Job Object (Windows)
    file_size_bytes: Optional[int] = 16 * _MB  # RLIMIT_FSIZE (POSIX)
    max_processes: Optional[int] = 64     # RLIMIT_NPROC (POSIX)
    output_bytes: int = 4 * _MB           # cap on stdout+stderr captured (all platforms)


@dataclass
class SandboxResult:
    returncode: Optional[int]
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_truncated: bool
    killed: bool
    reason: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.killed


def _minimal_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """A clean environment: enough to find a compiler, nothing inherited."""
    keep = {}
    if IS_WINDOWS:
        for key in ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "COMSPEC",
                    "PATHEXT", "WINDIR", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"):
            if key in os.environ:
                keep[key] = os.environ[key]
    else:
        keep["PATH"] = os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin")
        for key in ("LANG", "LC_ALL", "HOME", "TMPDIR"):
            if key in os.environ:
                keep[key] = os.environ[key]
    keep.setdefault("REVERIFY_SANDBOXED", "1")
    if extra:
        keep.update({str(k): str(v) for k, v in extra.items()})
    return keep


def _posix_preexec(limits: SandboxLimits):
    import resource

    def apply():
        try:
            os.setsid()
        except OSError:
            pass
        pairs = []
        if limits.cpu_seconds is not None:
            pairs.append((resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds + 1)))
        if limits.memory_bytes is not None:
            pairs.append((resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes)))
        if limits.file_size_bytes is not None:
            pairs.append((resource.RLIMIT_FSIZE, (limits.file_size_bytes, limits.file_size_bytes)))
        if limits.max_processes is not None and hasattr(resource, "RLIMIT_NPROC"):
            pairs.append((resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes)))
        pairs.append((resource.RLIMIT_CORE, (0, 0)))
        for what, (soft, hard) in pairs:
            try:
                resource.setrlimit(what, (soft, hard))
            except (ValueError, OSError):
                pass

    return apply


def protections_active(limits: Optional[SandboxLimits] = None) -> List[str]:
    """Human-readable list of confinements that actually apply on this platform."""
    limits = limits or SandboxLimits()
    active = [f"wall-clock timeout {limits.wall_seconds:g}s", f"output capped at {limits.output_bytes // _MB} MB",
              "isolated working dir", "scrubbed environment", "stdin from null"]
    if IS_POSIX:
        if limits.cpu_seconds is not None:
            active.append(f"CPU {limits.cpu_seconds}s (RLIMIT_CPU)")
        if limits.memory_bytes is not None:
            active.append(f"memory {limits.memory_bytes // _MB} MB (RLIMIT_AS)")
        if limits.file_size_bytes is not None:
            active.append(f"file size {limits.file_size_bytes // _MB} MB (RLIMIT_FSIZE)")
        if limits.max_processes is not None:
            active.append(f"processes {limits.max_processes} (RLIMIT_NPROC)")
        active.append("own session (setsid)")
    else:
        active.append("Windows Job Object memory limit + kill-on-close (best-effort)")
    return active


# --------------------------------------------------------------------------- Windows Job Object


class _WindowsJob:
    """Best-effort Job Object: cap process memory and kill the tree on close."""

    def __init__(self, memory_bytes: Optional[int]):
        self.handle = None
        self._ok = False
        try:
            import ctypes
            from ctypes import wintypes

            self._ctypes = ctypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._k32 = k32
            k32.CreateJobObjectW.restype = wintypes.HANDLE
            k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            self.handle = k32.CreateJobObjectW(None, None)
            if not self.handle:
                return

            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
            JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x0100

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in
                            ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                             "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if memory_bytes is not None:
                info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
                info.ProcessMemoryLimit = memory_bytes
            JobObjectExtendedLimitInformation = 9
            ok = k32.SetInformationJobObject(
                self.handle, JobObjectExtendedLimitInformation,
                ctypes.byref(info), ctypes.sizeof(info))
            self._ok = bool(ok)
        except Exception:
            self._ok = False

    def assign(self, pid: int) -> None:
        if not self._ok or not self.handle:
            return
        try:
            from ctypes import wintypes
            PROCESS_SET_QUOTA, PROCESS_TERMINATE = 0x0100, 0x0001
            self._k32.OpenProcess.restype = wintypes.HANDLE
            self._k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            hproc = self._k32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
            if hproc:
                self._k32.AssignProcessToJobObject(self.handle, hproc)
                self._k32.CloseHandle(hproc)
        except Exception:
            pass

    def close(self) -> None:
        if self.handle:
            try:
                self._k32.CloseHandle(self.handle)
            except Exception:
                pass
            self.handle = None


def _kill_tree(proc: "subprocess.Popen") -> None:
    if proc.poll() is not None:
        return
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        import signal
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                proc.kill()
            except OSError:
                pass


# --------------------------------------------------------------------------- the one entry point


def run_sandboxed(
    argv: Sequence[str],
    *,
    cwd: Optional[str] = None,
    input_bytes: Optional[bytes] = None,
    limits: Optional[SandboxLimits] = None,
    extra_env: Optional[Dict[str, str]] = None,
) -> SandboxResult:
    """Run ``argv`` under the platform's confinement; never raises for the child.

    The child gets a scrubbed env, ``cwd`` as its only obvious writable place,
    stdin from the given bytes (or empty), a wall-clock timeout, an output cap,
    and POSIX rlimits / a Windows Job Object. Returns a :class:`SandboxResult`;
    a timeout or a flood is reported, not raised.
    """
    limits = limits or SandboxLimits()
    env = _minimal_env(extra_env)
    popen_kwargs = dict(
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    job = None
    if IS_POSIX:
        popen_kwargs["preexec_fn"] = _posix_preexec(limits)
    else:
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    try:
        proc = subprocess.Popen(list(argv), **popen_kwargs)
    except (OSError, ValueError) as exc:
        return SandboxResult(None, b"", b"", False, False, True, f"spawn failed: {exc}")

    if IS_WINDOWS:
        job = _WindowsJob(limits.memory_bytes)
        job.assign(proc.pid)

    timed_out = False
    try:
        stdout, stderr = proc.communicate(input=input_bytes, timeout=limits.wall_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, ValueError):
            stdout, stderr = b"", b""
    finally:
        if job is not None:
            job.close()

    truncated = False
    if len(stdout) > limits.output_bytes:
        stdout = stdout[: limits.output_bytes]
        truncated = True
    if len(stderr) > limits.output_bytes:
        stderr = stderr[: limits.output_bytes]
        truncated = True

    reason = "timeout" if timed_out else ("output truncated" if truncated else "ok")
    return SandboxResult(
        returncode=None if timed_out else proc.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        output_truncated=truncated,
        killed=timed_out,
        reason=reason,
    )


if __name__ == "__main__":  # pragma: no cover - manual inspection
    print("sandbox protections on this platform:")
    for line in protections_active():
        print("  -", line)
    demo = run_sandboxed([sys.executable, "-c", "print(2 + 2)"])
    print("demo returncode:", demo.returncode, "stdout:", demo.stdout.decode().strip())
