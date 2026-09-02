import unittest
import sys
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from frida_bridge import FridaScriptGenerator


class TestFridaBridge(unittest.TestCase):
    def test_generate_function_hook(self):
        script = FridaScriptGenerator.generate_function_hook(
            target_symbol="CryptHashData",
            module_name="advapi32.dll",
            arg_count=4,
            log_backtrace=True,
            replace_return="0x1",
        )
        self.assertIn("CryptHashData", script)
        self.assertIn("advapi32.dll", script)
        self.assertIn("Interceptor.attach", script)
        self.assertIn("Thread.backtrace", script)
        self.assertIn('retval.replace(ptr("0x1"))', script)

    def test_generate_anti_debug(self):
        script = FridaScriptGenerator.generate_anti_debug_bypass()
        self.assertIn("IsDebuggerPresent", script)
        self.assertIn("CheckRemoteDebuggerPresent", script)
        self.assertIn("NtQueryInformationProcess", script)

    def test_generate_memory_patch(self):
        script = FridaScriptGenerator.generate_memory_patch(
            module_name="target.exe",
            offset_hex="0x1234",
            patch_bytes_hex="9090C3",
        )
        self.assertIn("target.exe", script)
        self.assertIn("0x1234", script)
        self.assertIn("0x90, 0x90, 0xC3", script)


if __name__ == "__main__":
    unittest.main()
