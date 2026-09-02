# -*- coding: utf-8 -*-
"""Model Context Protocol (MCP) Standard Stdio Server for reverify.

Implements the official JSON-RPC 2.0 MCP standard (stdio transport).
Enables seamless, native zero-configuration tool calling for:
- OpenCode
- Claude Desktop / Claude Code
- Cursor IDE / Windsurf
- VS Code (Cline / Continue.dev / Roo Code)
"""

import sys
import json
from typing import Dict, Any, List

try:  # installed package
    from .binary import parse_binary
    from .disasm import Disassembler, pattern_scan
    from .protocol_parser import ProtobufDissector, format_hexdump
    from .verifier import Verifier, Claim
    from .backends import backend_report
except ImportError:  # run directly: ``python reverify/mcp_server.py``
    from binary import parse_binary
    from disasm import Disassembler, pattern_scan
    from protocol_parser import ProtobufDissector, format_hexdump
    from verifier import Verifier, Claim
    from backends import backend_report


TOOLS_MANIFEST = [
    {
        "name": "re_auto_triage",
        "description": "Automatically inspects binary format, architecture, sections, and top symbols.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Absolute or relative file path"}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "re_parse_pe",
        "description": "Extracts PE32/PE32+ headers, sections, imported DLL functions, and exports.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Target PE executable/DLL path"}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "re_parse",
        "description": "Parses PE, ELF or Mach-O: format, arch, entry point, sections, imports, exports (lief when installed).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Target binary path"}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "re_backends",
        "description": "Reports which engines are active: capstone (disassembly), unicorn (emulation), lief (parsing).",
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "re_pattern_scan",
        "description": "Scans binary data for hex AOB signatures with wildcards (e.g. '48 89 ?? 24').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Target binary file path"},
                "pattern": {"type": "string", "description": "Hex pattern with ?? wildcards"}
            },
            "required": ["file_path", "pattern"]
        }
    },
    {
        "name": "re_disasm",
        "description": "Disassembles raw hex machine code opcodes into x86/x64 assembly instructions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hex_bytes": {"type": "string", "description": "Hexadecimal byte stream"},
                "arch": {"type": "string", "enum": ["x86_64", "x86_32"], "default": "x86_64"}
            },
            "required": ["hex_bytes"]
        }
    },
    {
        "name": "re_verify_claim",
        "description": (
            "The core Reverify loop: check a claim/hypothesis about a binary against the "
            "deterministic tools and return VERIFIED / REFUTED / INCONCLUSIVE with observed "
            "evidence. Use this before reporting any structural fact so it is grounded in the "
            "bytes, not guessed. Claim kinds: bytes_at, pattern_present, string_present, "
            "instructions, emulate_result, protobuf_field, import_present, export_present, "
            "section_present (pe_import is an alias)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Target binary file path"},
                "claims": {
                    "type": "array",
                    "description": "One or more claim objects, each {kind, params, note?}",
                    "items": {"type": "object"}
                }
            },
            "required": ["file_path", "claims"]
        }
    }
]


def handle_tool_call(name: str, arguments: Dict[str, Any]) -> str:
    """Dispatches tool call to underlying deterministic reverify engines."""
    try:
        if name == "re_auto_triage":
            with open(arguments["file_path"], "rb") as f:
                data = f.read()
            info = parse_binary(data)
            out = {"size": len(data), "binary": info.summary(), "sample_bytes": format_hexdump(data[:64])}
            return json.dumps(out, indent=2, default=str)

        elif name in ("re_parse_pe", "re_parse"):
            with open(arguments["file_path"], "rb") as f:
                data = f.read()
            return json.dumps(parse_binary(data).to_dict(), indent=2, default=str)

        elif name == "re_backends":
            return json.dumps(backend_report(), indent=2)

        elif name == "re_pattern_scan":
            fpath = arguments["file_path"]
            pattern = arguments["pattern"]
            with open(fpath, "rb") as f:
                data = f.read()
            matches = pattern_scan(data, pattern)
            return json.dumps({"pattern": pattern, "matches": [hex(m) for m in matches]}, indent=2)

        elif name == "re_disasm":
            hex_bytes = arguments["hex_bytes"]
            arch = arguments.get("arch", "x86_64")
            raw = bytes.fromhex(hex_bytes.replace(" ", ""))
            dis = Disassembler(arch=arch)
            insns = dis.disassemble(raw, base_address=0x1000)
            return json.dumps([{"address": hex(i.address), "mnemonic": i.mnemonic, "op_str": i.op_str} for i in insns], indent=2)

        elif name == "re_verify_claim":
            fpath = arguments["file_path"]
            claims = arguments["claims"]
            if isinstance(claims, dict):
                claims = [claims]
            with open(fpath, "rb") as f:
                data = f.read()
            verifier = Verifier(data)
            report = verifier.verify_all([Claim.from_dict(c) for c in claims])
            return json.dumps(report, indent=2, ensure_ascii=False)

        else:
            return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def run_mcp_server() -> None:
    """Runs standard MCP stdio JSON-RPC 2.0 loop."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "reverify-mcp",
                        "version": "0.0.0"
                    }
                }
            }
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": TOOLS_MANIFEST
                }
            }
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            result_text = handle_tool_call(tool_name, tool_args)
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result_text
                        }
                    ]
                }
            }
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    run_mcp_server()
