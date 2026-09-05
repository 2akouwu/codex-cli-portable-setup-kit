"""The native-execution sandbox actually confines: timeout, output cap, memory, env, stdin.

Uses the Python interpreter as the stand-in "untrusted program" so the test needs
no C compiler. POSIX resource limits are checked where the platform enforces them.
"""

import os
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from sandbox import run_sandboxed, SandboxLimits, protections_active, IS_POSIX  # noqa: E402

PY = sys.executable
IS_LINUX = sys.platform.startswith("linux")


def py(code, **kw):
    return run_sandboxed([PY, "-c", code], **kw)


class TestBasics(unittest.TestCase):
    def test_clean_run(self):
        r = py("print(2 + 2)")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.ok)
        self.assertEqual(r.stdout.decode().strip(), "4")
        self.assertFalse(r.timed_out)

    def test_nonzero_exit_is_not_ok(self):
        r = py("import sys; sys.exit(3)")
        self.assertEqual(r.returncode, 3)
        self.assertFalse(r.ok)

    def test_stdin_is_delivered(self):
        r = py("import sys; sys.stdout.write(sys.stdin.read().strip().upper())", input_bytes=b"hello")
        self.assertEqual(r.stdout.decode().strip(), "HELLO")

    def test_spawn_failure_is_reported_not_raised(self):
        r = run_sandboxed([str(tools_root / "does-not-exist-xyz")])
        self.assertIsNone(r.returncode)
        self.assertTrue(r.killed)
        self.assertIn("spawn failed", r.reason)

    def test_protections_list_mentions_platform_limits(self):
        active = protections_active()
        joined = " ".join(active)
        self.assertIn("timeout", joined)
        self.assertIn("output capped", joined)
        if IS_POSIX:
            self.assertIn("RLIMIT_AS", joined)
        else:
            self.assertIn("Job Object", joined)


class TestConfinement(unittest.TestCase):
    def test_wall_timeout_kills_a_sleeper(self):
        # 3s wall (well under the 30s sleep, comfortably above interpreter cold-start under load)
        r = py("import time; time.sleep(30)", limits=SandboxLimits(wall_seconds=3.0))
        self.assertTrue(r.timed_out)
        self.assertTrue(r.killed)
        self.assertIsNone(r.returncode)

    def test_output_is_capped(self):
        r = py("import sys; sys.stdout.write('x' * 5_000_000)",
               limits=SandboxLimits(wall_seconds=15, output_bytes=2000))
        self.assertTrue(r.output_truncated)
        self.assertLessEqual(len(r.stdout), 2000)

    def test_environment_is_scrubbed(self):
        os.environ["REVERIFY_TEST_SECRET"] = "leak-me"
        try:
            r = py("import os; print(os.environ.get('REVERIFY_TEST_SECRET', 'none'), os.environ.get('REVERIFY_SANDBOXED', 'no'))")
        finally:
            os.environ.pop("REVERIFY_TEST_SECRET", None)
        out = r.stdout.decode().strip().split()
        self.assertEqual(out[0], "none")      # inherited secret does not reach the child
        self.assertEqual(out[1], "1")         # but the sandbox marker does
        # extra_env can still inject what the caller intends
        r2 = py("import os; print(os.environ.get('WANTED', 'no'))", extra_env={"WANTED": "yes"})
        self.assertEqual(r2.stdout.decode().strip(), "yes")

    @unittest.skipUnless(IS_LINUX, "RLIMIT_AS is only reliably enforced on Linux")
    def test_memory_limit_bites(self):
        r = py("bytearray(400 * 1024 * 1024)", limits=SandboxLimits(wall_seconds=15, memory_bytes=64 * 1024 * 1024))
        self.assertFalse(r.ok)                 # MemoryError -> nonzero exit (or killed)

    @unittest.skipUnless(IS_LINUX, "RLIMIT_CPU timing is platform-specific")
    def test_cpu_limit_bites(self):
        r = py("x = 0\nwhile True: x += 1", limits=SandboxLimits(wall_seconds=30, cpu_seconds=1))
        # CPU limit fires (SIGXCPU) before the 30s wall clock; either way it is not a clean 0
        self.assertFalse(r.ok)
        self.assertFalse(r.timed_out)          # killed by CPU limit, not the wall clock


if __name__ == "__main__":
    unittest.main()
