"""Frida dynamic instrumentation template generator and bridge."""

from typing import Dict, Any, List, Optional


class FridaScriptGenerator:
    """Generates standard and robust Frida dynamic instrumentation scripts."""

    @staticmethod
    def generate_function_hook(
        target_symbol: str,
        module_name: Optional[str] = None,
        arg_count: int = 4,
        log_backtrace: bool = False,
        replace_return: Optional[str] = None,
    ) -> str:
        """Generate a Frida interceptor script for a specific function or offset."""
        target_expr = f'Module.findExportByName("{module_name}", "{target_symbol}")' if module_name else f'Module.findExportByName(null, "{target_symbol}")'
        if target_symbol.startswith("0x") or target_symbol.startswith("0X"):
            if module_name:
                target_expr = f'Module.findBaseAddress("{module_name}").add({target_symbol})'
            else:
                target_expr = f'ptr("{target_symbol}")'

        args_log = []
        for i in range(arg_count):
            args_log.append(f'        console.log("    arg[{i}]: " + args[{i}] + " (int: " + args[{i}].toInt32() + ")");')
        args_log_str = "\n".join(args_log)

        backtrace_snippet = """
        console.log("    Backtrace:\\n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\\n    "));
""" if log_backtrace else ""

        replace_snippet = f"""
        console.log("    Replacing retval " + retval + " with {replace_return}");
        retval.replace(ptr("{replace_return}"));
""" if replace_return is not None else ""

        script = f"""// Auto-generated Frida Hook Script for {target_symbol}
(function() {{
    const target = {target_expr};
    if (!target || target.isNull()) {{
        console.error("[!] Target not found: {target_symbol}");
        return;
    }}
    console.log("[+] Hooking {target_symbol} at " + target);

    Interceptor.attach(target, {{
        onEnter: function(args) {{
            console.log("[*] Called {target_symbol}");
{args_log_str}{backtrace_snippet}
        }},
        onLeave: function(retval) {{
            console.log("[*] {target_symbol} return: " + retval);{replace_snippet}
        }}
    }});
}})();
"""
        return script

    @staticmethod
    def generate_anti_debug_bypass() -> str:
        """Generate a Frida script to bypass common Windows anti-debug APIs."""
        return """// Frida Windows Anti-Debug Bypass Script
(function() {
    console.log("[*] Installing Anti-Debug Bypasses...");

    // IsDebuggerPresent
    const pIsDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
    if (pIsDebuggerPresent) {
        Interceptor.attach(pIsDebuggerPresent, {
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    console.log("[+] Patched IsDebuggerPresent -> 0");
                    retval.replace(ptr(0));
                }
            }
        });
    }

    // CheckRemoteDebuggerPresent
    const pCheckRemote = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
    if (pCheckRemote) {
        Interceptor.attach(pCheckRemote, {
            onEnter: function(args) {
                this.pbDebuggerPresent = args[1];
            },
            onLeave: function(retval) {
                if (this.pbDebuggerPresent && !this.pbDebuggerPresent.isNull()) {
                    this.pbDebuggerPresent.writeU32(0);
                    console.log("[+] Patched CheckRemoteDebuggerPresent flag -> 0");
                }
            }
        });
    }

    // NtQueryInformationProcess (ProcessDebugPort = 7)
    const pNtQuery = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
    if (pNtQuery) {
        Interceptor.attach(pNtQuery, {
            onEnter: function(args) {
                this.infoClass = args[1].toInt32();
                this.infoBuffer = args[2];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.infoBuffer && !this.infoBuffer.isNull()) {
                    if (this.infoClass === 7) { // ProcessDebugPort
                        this.infoBuffer.writePointer(ptr(0));
                        console.log("[+] Patched NtQueryInformationProcess (ProcessDebugPort) -> 0");
                    }
                }
            }
        });
    }

    console.log("[+] Anti-Debug Bypasses Installed Successfully.");
})();
"""

    @staticmethod
    def generate_memory_patch(module_name: str, offset_hex: str, patch_bytes_hex: str) -> str:
        """Generate a Frida script to write byte patches in memory."""
        byte_array_str = ", ".join(f"0x{patch_bytes_hex[i:i+2]}" for i in range(0, len(patch_bytes_hex), 2))
        return f"""// Frida Memory Patcher
(function() {{
    const base = Module.findBaseAddress("{module_name}");
    if (!base) {{
        console.error("[!] Module {module_name} not loaded yet");
        return;
    }}
    const target = base.add({offset_hex});
    const patch = [{byte_array_str}];

    Memory.protect(target, patch.length, 'rwx');
    Memory.writeByteArray(target, patch);
    console.log("[+] Patched " + patch.length + " bytes at " + target);
}})();
"""
