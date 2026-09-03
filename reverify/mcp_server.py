# -*- coding: utf-8 -*-
"""Model Context Protocol (MCP) Standard Stdio Server for reverify.

Implements the official JSON-RPC 2.0 MCP standard (stdio transport).
Enables seamless, native zero-configuration tool calling for:
- OpenCode
- Claude Desktop / Claude Code
- Cursor IDE / Windsurf
- VS Code (Cline / Continue.dev / Roo Code)

State that survives the host's context: every ``re_verify_claim`` call records
what the tools verified, observed, proved or refuted into a durable per-binary
ledger (``.reverify/ledger/``, override with ``REVERIFY_LEDGER_DIR``). After the
host compacts or clears its context, ``re_ledger`` (or the ``reverify://ledger``
resources) hands the grounded state back — bounded, and without a summary in
between.
"""

import sys
import json
from typing import Dict, Any, List

try:  # installed package
    from .binary import parse_binary
    from .disasm import Disassembler, pattern_scan
    from .protocol_parser import ProtobufDissector, format_hexdump
    from .verifier import Verifier, Claim, summarize, claim_key, VERIFIED
    from .backends import backend_report
    from .ledger import Ledger, list_ledgers, LEDGER_INSTRUCTIONS
except ImportError:  # run directly: ``python reverify/mcp_server.py``
    from binary import parse_binary
    from disasm import Disassembler, pattern_scan
    from protocol_parser import ProtobufDissector, format_hexdump
    from verifier import Verifier, Claim, summarize, claim_key, VERIFIED
    from backends import backend_report
    from ledger import Ledger, list_ledgers, LEDGER_INSTRUCTIONS

try:
    from ._version import __version__ as SERVER_VERSION
except ImportError:
    from _version import __version__ as SERVER_VERSION


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
            "bytes, not guessed. Claim kinds: bytes_at, u16/u32/u64_at, pattern_present, "
            "string_present, instructions, emulate_result, behavior_equiv, prove_equiv, "
            "protobuf_field, import_present, export_present, section_present (pe_import is an "
            "alias). Grounded results are recorded in the binary's durable ledger automatically, "
            "so they survive a context reset; a claim already in the ledger comes back with "
            "known=true and weight 0."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Target binary file path"},
                "claims": {
                    "type": "array",
                    "description": "One or more claim objects, each {kind, params, note?}",
                    "items": {"type": "object"}
                },
                "record": {"type": "boolean", "default": True,
                           "description": "Record grounded results in the durable ledger (default true)"},
                "goal": {"type": "string", "description": "Optional: what you are trying to establish (kept in the ledger)"},
                "session": {"type": "string", "description": "Optional session label for the ledger"}
            },
            "required": ["file_path", "claims"]
        }
    },
    {
        "name": "re_ledger",
        "description": (
            "Restore or manage the durable ledger of grounded facts for a binary — everything the "
            "tools verified, observed, proved or refuted in earlier calls, including earlier "
            "sessions. Call this after /clear, compaction or a restart instead of re-deriving "
            "facts. action=show returns a bounded view (max_facts) plus known-false claims; "
            "action=index returns a one-line summary; action=clear discards the ledger."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Target binary file path"},
                "action": {"type": "string", "enum": ["show", "index", "clear"], "default": "show"},
                "max_facts": {"type": "integer", "default": 30,
                              "description": "How many facts to return (proof-grade facts are always kept)"},
                "max_false": {"type": "integer", "default": 8, "description": "How many refuted claims to list"}
            },
            "required": ["file_path"]
        }
    }
]


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def handle_tool_call(name: str, arguments: Dict[str, Any]) -> str:
    """Dispatches tool call to underlying deterministic reverify engines."""
    try:
        if name == "re_auto_triage":
            data = _read(arguments["file_path"])
            info = parse_binary(data)
            out = {"size": len(data), "binary": info.summary(), "sample_bytes": format_hexdump(data[:64])}
            return json.dumps(out, indent=2, default=str)

        elif name in ("re_parse_pe", "re_parse"):
            data = _read(arguments["file_path"])
            return json.dumps(parse_binary(data).to_dict(), indent=2, default=str)

        elif name == "re_backends":
            return json.dumps(backend_report(), indent=2)

        elif name == "re_pattern_scan":
            fpath = arguments["file_path"]
            pattern = arguments["pattern"]
            data = _read(fpath)
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
            data = _read(fpath)
            verifier = Verifier(data)
            report = verifier.verify_all([Claim.from_dict(c) for c in claims])
            record = bool(arguments.get("record", True))
            led = Ledger.for_bytes(data, persist=record, file_path=fpath)
            known_keys = led.fact_keys()
            known = 0
            for r in report["results"]:
                if r["verdict"] == VERIFIED and claim_key(r["kind"], r.get("params", {})) in known_keys:
                    r["known"] = True
                    known += 1
            if known:
                report = summarize(report["results"], min_information=report.get("min_information", 1.0))
            added = led.record(report["results"], goal=arguments.get("goal"), session=arguments.get("session"))
            path = led.save()
            report["ledger"] = {
                "path": str(path) if path else None,
                "recorded": added,
                **led.counts(),
                "hint": "grounded results are kept on disk; after a context reset call re_ledger to restore them",
            }
            return json.dumps(report, indent=2, ensure_ascii=False, default=str)

        elif name == "re_ledger":
            fpath = arguments["file_path"]
            action = str(arguments.get("action", "show"))
            max_facts = int(arguments.get("max_facts", 30))
            max_false = int(arguments.get("max_false", 8))
            led = Ledger.for_file(fpath)
            if action == "clear":
                led.clear()
                return json.dumps({"cleared": True, "path": str(led.path) if led.path else None}, indent=2)
            if action == "index":
                return json.dumps({"index": led.index_line(), **led.summary()}, indent=2, ensure_ascii=False)
            return json.dumps({
                "summary": led.summary(),
                "established": led.established(max_facts),
                "known_false": led.known_false(max_false),
                "context": led.context_text(max_facts, max_false),
            }, indent=2, ensure_ascii=False, default=str)

        else:
            return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def _resource_uri(led: Ledger) -> str:
    return f"reverify://ledger/{led.sha256[:24]}"


def handle_resources_list() -> Dict[str, Any]:
    return {
        "resources": [
            {
                "uri": _resource_uri(led),
                "name": led.label(),
                "description": led.index_line(),
                "mimeType": "text/plain",
            }
            for led in list_ledgers()
        ]
    }


def handle_resources_read(uri: str) -> Dict[str, Any]:
    for led in list_ledgers():
        if _resource_uri(led) == uri:
            return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": led.context_text()}]}
    raise KeyError(uri)


def handle_request(req: Dict[str, Any]):
    """One JSON-RPC request -> response dict, or None for a notification."""
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {}) or {}
    if req_id is None or (isinstance(method, str) and method.startswith("notifications/")):
        return None  # notifications get no response (JSON-RPC 2.0)

    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": "reverify-mcp", "version": SERVER_VERSION},
            "instructions": LEDGER_INSTRUCTIONS,
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS_MANIFEST}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": handle_tool_call(params.get("name"), params.get("arguments", {}) or {})}]}
    elif method == "resources/list":
        result = handle_resources_list()
    elif method == "resources/read":
        try:
            result = handle_resources_read(str(params.get("uri", "")))
        except KeyError:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32002, "message": f"Resource not found: {params.get('uri')}"}}
    else:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


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
        resp = handle_request(req)
        if resp is None:
            continue
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    run_mcp_server()
