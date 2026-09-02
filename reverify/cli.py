#!/usr/bin/env python3
"""Unified CLI entrypoint for Reverse Engineering Toolkit."""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

# Add parent directory to path so re_toolkit imports work when executed directly
toolkit_root = Path(__file__).resolve().parent.parent
if str(toolkit_root) not in sys.path:
    sys.path.insert(0, str(toolkit_root))

try:  # installed package (e.g. the ``reverify`` console script)
    from .pe_parser import PEParser, BinaryParseError
    from .disasm import Disassembler, pattern_scan, create_patch
    from .emulator import MicroEmulator
    from .protocol_parser import ProtobufDissector, TLVDissector, format_hexdump
    from .frida_bridge import FridaScriptGenerator
    from .boundary_auditor import run_full_security_audit, PathBoundaryAuditor, NetworkBoundaryAuditor
    from .verifier import Verifier, Claim
    from .agent import ReconstructionAgent, openai_proposer, demo_proposer
except ImportError:  # run directly as a script: ``python reverify/cli.py ...``
    from pe_parser import PEParser, BinaryParseError
    from disasm import Disassembler, pattern_scan, create_patch
    from emulator import MicroEmulator
    from protocol_parser import ProtobufDissector, TLVDissector, format_hexdump
    from frida_bridge import FridaScriptGenerator
    from boundary_auditor import run_full_security_audit, PathBoundaryAuditor, NetworkBoundaryAuditor
    from verifier import Verifier, Claim
    from agent import ReconstructionAgent, openai_proposer, demo_proposer


def load_input_bytes(input_val: str, offset: int = 0, length: int = 0) -> bytes:
    """Load bytes from a hex string or from a file path."""
    if os.path.exists(input_val):
        with open(input_val, "rb") as f:
            if offset > 0:
                f.seek(offset)
            if length > 0:
                return f.read(length)
            return f.read()
    else:
        # Treat as hex string
        clean_hex = "".join(input_val.split()).replace("0x", "").replace("0X", "")
        return bytes.fromhex(clean_hex)


def extract_strings(data: bytes, min_len: int = 4) -> List[Dict[str, Any]]:
    """Extract ASCII and UTF-16LE strings with file offsets."""
    results = []
    # ASCII strings
    ascii_re = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in ascii_re.finditer(data):
        results.append({
            "offset": hex(m.start()),
            "type": "ASCII",
            "string": m.group().decode("latin1", errors="ignore"),
        })
    # Unicode (UTF-16LE) strings
    uni_re = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    for m in uni_re.finditer(data):
        try:
            s = m.group().decode("utf-16le", errors="ignore")
            results.append({
                "offset": hex(m.start()),
                "type": "UTF-16LE",
                "string": s,
            })
        except Exception:
            pass
    return sorted(results, key=lambda x: int(x["offset"], 16))


def auto_triage(data: bytes, filename: str = "") -> Dict[str, Any]:
    """Auto-detect binary format and extract top-level metadata."""
    report: Dict[str, Any] = {"filename": filename, "size": len(data), "magic": data[:4].hex()}
    if data.startswith(b"MZ"):
        report["type"] = "Windows PE Binary (EXE/DLL/SYS)"
        try:
            parser = PEParser(data)
            report["pe_summary"] = parser.summary()
            report["sections"] = [s["Name"] for s in parser.sections]
            report["imports"] = parser.imports
            report["exports"] = [e["name"] for e in parser.exports[:25]]
        except Exception as e:
            report["pe_error"] = str(e)
    elif data.startswith(b"\x7fELF"):
        report["type"] = "Linux ELF Binary"
    elif data.startswith(b"PK\x03\x04"):
        report["type"] = "ZIP Archive / Package"
    else:
        report["type"] = "Raw Binary / Memory Dump / Protocol Stream"
        # Try Protobuf
        pb = ProtobufDissector.dissect(data[:512])
        if pb and not any("error" in item for item in pb):
            report["protobuf_preview"] = pb[:5]
    # Extract top strings preview
    strings = extract_strings(data[:65536], min_len=5)
    report["top_strings"] = [s["string"] for s in strings[:15]]
    return report


def cmd_parse_pe(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.file)
    parser = PEParser(data)
    if args.json:
        out = {
            "summary": parser.summary(),
            "sections": parser.sections,
            "imports": parser.imports,
            "exports": parser.exports,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        summary = parser.summary()
        print("=== PE Binary Summary ===")
        print(f"Format:       {summary['format']} ({summary['machine']})")
        print(f"64-bit:       {summary['is_64bit']}")
        print(f"EntryPoint:   {summary['entrypoint']}")
        print(f"ImageBase:    {summary['image_base']}")
        print(f"Sections:     {', '.join(summary['sections'])}")
        print(f"Imported DLLs: {', '.join(summary['imported_dlls'])}")
        print(f"Exports:      {summary['export_count']} exported symbols")


def cmd_disasm(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target, offset=args.offset, length=args.length)
    disasm = Disassembler(arch=args.arch)
    instructions = disasm.disassemble(data, base_address=args.base)
    if args.json:
        print(json.dumps([ins.to_dict() for ins in instructions], indent=2))
    else:
        for ins in instructions:
            print(ins)


def cmd_pattern_scan(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    matches = pattern_scan(data, args.pattern)
    results = [{"offset": hex(m), "address": hex(args.base + m)} for m in matches]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"[+] Found {len(matches)} matches for pattern '{args.pattern}':")
        for r in results:
            print(f"  Offset: {r['offset']} | Address: {r['address']}")


def cmd_strings(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.file)
    strings = extract_strings(data, min_len=args.min_len)
    if args.json:
        print(json.dumps(strings, indent=2, ensure_ascii=False))
    else:
        for s in strings:
            print(f"{s['offset']} [{s['type']}]: {s['string']}")


def cmd_diff_patch(args: argparse.Namespace) -> None:
    orig = load_input_bytes(args.orig)
    patched = load_input_bytes(args.patched)
    patches = create_patch(orig, patched, base_address=args.base)
    if args.json:
        print(json.dumps(patches, indent=2))
    else:
        print(f"[+] Found {len(patches)} patch differences:")
        for p in patches:
            print(f"  Offset: {p['offset']} ({p['length']} bytes): {p['original_bytes']} -> {p['patched_bytes']}")


def cmd_auto(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    filename = os.path.basename(args.target) if os.path.exists(args.target) else "raw_input"
    report = auto_triage(data, filename=filename)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"=== Auto-Triage: {report.get('filename')} ({report.get('size')} bytes) ===")
        print(f"Detected Type: {report.get('type')}")
        if "pe_summary" in report:
            ps = report["pe_summary"]
            print(f"PE Architecture: {ps['machine']} (64-bit: {ps['is_64bit']})")
            print(f"Sections: {', '.join(report.get('sections', []))}")
            print(f"Imported DLLs: {', '.join(ps.get('imported_dlls', []))}")
        if "top_strings" in report and report["top_strings"]:
            print(f"Strings Preview: {', '.join(report['top_strings'][:8])}")


def cmd_decode_protobuf(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    tree = ProtobufDissector.dissect(data)
    print(json.dumps(tree, indent=2, ensure_ascii=False))


def cmd_decode_tlv(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    tlv_list = TLVDissector.dissect(data, type_len=args.type_len, length_len=args.len_len)
    print(json.dumps(tlv_list, indent=2, ensure_ascii=False))


def cmd_emulate(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.code)
    emu = MicroEmulator(arch=args.arch)
    emu.load_code(data, base_address=args.base)
    state = emu.run(max_steps=args.max_steps)
    print(json.dumps(state, indent=2, ensure_ascii=False))


def cmd_gen_hook(args: argparse.Namespace) -> None:
    script = FridaScriptGenerator.generate_function_hook(
        target_symbol=args.symbol,
        module_name=args.module,
        arg_count=args.args_count,
        log_backtrace=args.backtrace,
        replace_return=args.replace_ret,
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(script)
        print(f"[+] Hook script saved to {args.output}")
    else:
        print(script)


def cmd_hexdump(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target, offset=args.offset, length=args.length)
    print(format_hexdump(data, base_address=args.base))


def cmd_reconstruct(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    if args.mock:
        propose = demo_proposer(data)
    else:
        propose = openai_proposer(model=args.model, base_url=args.base_url, api_key=args.api_key)
    agent = ReconstructionAgent(data, propose, max_rounds=args.rounds)
    result = agent.run(args.goal)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("=== Reverify: closed reconstruction loop ===")
        print(f"Goal: {result['goal']}")
        for h in result["history"]:
            rep = h["report"]
            print(
                f"  round {h['round']}: {rep['verified']} verified, "
                f"{rep['refuted']} refuted, {rep['inconclusive']} inconclusive"
            )
        status = "GROUNDED" if result["grounded"] else "NOT grounded"
        print(f"\n{status} after {result['rounds_used']} round(s).")
        if result["grounded"]:
            for r in result["verified_claims"]:
                note = f" - {r['note']}" if r.get("note") else ""
                print(f"  [VERIFIED] {r['kind']}{note}")
    if not result["grounded"]:
        sys.exit(2)


def cmd_verify(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)

    claims_data: List[Dict[str, Any]] = []
    if args.claims_file:
        with open(args.claims_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        claims_data = loaded if isinstance(loaded, list) else [loaded]
    elif args.claim:
        loaded = json.loads(args.claim)
        claims_data = loaded if isinstance(loaded, list) else [loaded]
    else:
        raise SystemExit("verify requires --claim '<json>' or --claims-file <path>")

    verifier = Verifier(data)
    report = verifier.verify_all([Claim.from_dict(c) for c in claims_data])

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=== Reverify: tool-grounded claim verification ===")
        symbols = {"VERIFIED": "[VERIFIED]", "REFUTED": "[REFUTED ]", "INCONCLUSIVE": "[INCONCL.]"}
        for r in report["results"]:
            mark = symbols.get(r["verdict"], r["verdict"])
            note = f" - {r['note']}" if r["note"] else ""
            print(f"{mark} {r['kind']}{note}")
            print(f"           {r['detail']}")
        print(
            f"\nGrounded {report['verified']}/{report['total_claims']} "
            f"(refuted {report['refuted']}, inconclusive {report['inconclusive']}). "
            f"Trustworthy reconstruction: {report['trustworthy']}"
        )
    # Non-zero exit if anything was refuted, so CI / agents can gate on it.
    if report["refuted"] > 0:
        sys.exit(2)


def cmd_audit_boundary(args: argparse.Namespace) -> None:
    workspace = args.workspace or os.getcwd()
    urls = args.urls.split(",") if args.urls else None
    report = run_full_security_audit(workspace, urls)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"=== Security Boundary Audit Report ===")
        print(f"Status:          {report['status']}")
        print(f"Workspace Root:  {report['workspace_root']}")
        print(f"Summary:         {report['summary']}")
        print("\n--- Network Boundaries Evaluated ---")
        for net in report["network_audit"]:
            state = "SAFE" if net["is_safe"] else "BLOCKED"
            print(f"[{state}] {net['url']}")
            for finding in net["findings"]:
                print(f"       -> {finding}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="reverify",
        description="Reverify - verified reverse engineering, protocol dissection, and emulation toolkit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # auto
    p_auto = subparsers.add_parser("auto", help="Automatically triage and inspect target binary")
    p_auto.add_argument("target", help="File path or hex stream")
    p_auto.add_argument("--json", action="store_true", help="Output full JSON triage report")
    p_auto.set_defaults(func=cmd_auto)

    # parse-pe
    p_pe = subparsers.add_parser("parse-pe", help="Parse PE32/PE32+ binary structure")
    p_pe.add_argument("file", help="Path to EXE/DLL/SYS file")
    p_pe.add_argument("--json", action="store_true", help="Output full JSON structure")
    p_pe.set_defaults(func=cmd_parse_pe)

    # pattern-scan
    p_scan = subparsers.add_parser("pattern-scan", help="Scan binary data for AOB hex pattern with wildcards")
    p_scan.add_argument("target", help="File path or hex string")
    p_scan.add_argument("--pattern", required=True, help="AOB pattern (e.g. '48 89 ?? 24 ?? 55')")
    p_scan.add_argument("--base", type=lambda x: int(x, 0), default=0, help="Base address")
    p_scan.add_argument("--json", action="store_true", help="Output JSON matches")
    p_scan.set_defaults(func=cmd_pattern_scan)

    # strings
    p_str = subparsers.add_parser("strings", help="Extract ASCII and Unicode strings from binary")
    p_str.add_argument("file", help="Path to binary file")
    p_str.add_argument("--min-len", type=int, default=4, help="Minimum string length")
    p_str.add_argument("--json", action="store_true", help="Output JSON list with offsets")
    p_str.set_defaults(func=cmd_strings)

    # diff-patch
    p_patch = subparsers.add_parser("diff-patch", help="Compare original and patched binaries and output patch diff")
    p_patch.add_argument("--orig", required=True, help="Path to original binary")
    p_patch.add_argument("--patched", required=True, help="Path to patched binary")
    p_patch.add_argument("--base", type=lambda x: int(x, 0), default=0, help="Base address")
    p_patch.add_argument("--json", action="store_true", help="Output JSON patches")
    p_patch.set_defaults(func=cmd_diff_patch)

    # disasm
    p_dis = subparsers.add_parser("disasm", help="Disassemble binary code or hex stream")
    p_dis.add_argument("target", help="Hex string or file path")
    p_dis.add_argument("--offset", type=lambda x: int(x, 0), default=0, help="File byte offset")
    p_dis.add_argument("--length", type=lambda x: int(x, 0), default=64, help="Byte length")
    p_dis.add_argument("--base", type=lambda x: int(x, 0), default=0x1000, help="Base address")
    p_dis.add_argument("--arch", default="x86_64", help="Architecture (x86, x86_64, arm, arm64)")
    p_dis.add_argument("--json", action="store_true", help="Output JSON instruction list")
    p_dis.set_defaults(func=cmd_disasm)

    # decode-protobuf
    p_pb = subparsers.add_parser("decode-protobuf", help="Dissect raw Protobuf binary stream")
    p_pb.add_argument("target", help="Hex string or file path")
    p_pb.set_defaults(func=cmd_decode_protobuf)

    # decode-tlv
    p_tlv = subparsers.add_parser("decode-tlv", help="Dissect TLV binary packet")
    p_tlv.add_argument("target", help="Hex string or file path")
    p_tlv.add_argument("--type-len", type=int, default=1, help="Type field length in bytes")
    p_tlv.add_argument("--len-len", type=int, default=2, help="Length field length in bytes")
    p_tlv.set_defaults(func=cmd_decode_tlv)

    # emulate
    p_emu = subparsers.add_parser("emulate", help="Emulate instruction execution")
    p_emu.add_argument("--code", required=True, help="Hex byte string of instructions")
    p_emu.add_argument("--base", type=lambda x: int(x, 0), default=0x1000, help="Base address")
    p_emu.add_argument("--arch", default="x86_64", help="Architecture (x86, x86_64)")
    p_emu.add_argument("--max-steps", type=int, default=100, help="Maximum execution steps")
    p_emu.set_defaults(func=cmd_emulate)

    # gen-hook
    p_hook = subparsers.add_parser("gen-hook", help="Generate Frida hook script")
    p_hook.add_argument("--symbol", required=True, help="Target function symbol or hex address")
    p_hook.add_argument("--module", help="Target module name (e.g. ntdll.dll)")
    p_hook.add_argument("--args-count", type=int, default=4, help="Number of arguments to log")
    p_hook.add_argument("--backtrace", action="store_true", help="Log accurate backtrace on enter")
    p_hook.add_argument("--replace-ret", help="Value/pointer to replace return value with")
    p_hook.add_argument("--output", help="Save script to file")
    p_hook.set_defaults(func=cmd_gen_hook)

    # hexdump
    p_hex = subparsers.add_parser("hexdump", help="Display formatted hexadecimal dump")
    p_hex.add_argument("target", help="Hex string or file path")
    p_hex.add_argument("--offset", type=lambda x: int(x, 0), default=0, help="File byte offset")
    p_hex.add_argument("--length", type=lambda x: int(x, 0), default=128, help="Byte length")
    p_hex.add_argument("--base", type=lambda x: int(x, 0), default=0, help="Base address")
    p_hex.set_defaults(func=cmd_hexdump)

    # reconstruct
    p_recon = subparsers.add_parser(
        "reconstruct",
        help="Closed loop: model proposes claims, the tools verify, iterate until grounded",
    )
    p_recon.add_argument("target", help="File path or hex stream to reconstruct facts about")
    p_recon.add_argument("--goal", required=True, help="What to reconstruct, in plain language")
    p_recon.add_argument("--rounds", type=int, default=4, help="Maximum propose/verify rounds")
    p_recon.add_argument("--model", help="Model name (defaults to OPENAI_MODEL or gpt-4o)")
    p_recon.add_argument("--api-key", help="API key (defaults to OPENAI_API_KEY env)")
    p_recon.add_argument("--base-url", help="API base URL (defaults to OPENAI_BASE_URL env)")
    p_recon.add_argument("--mock", action="store_true", help="Offline demo proposer, no network")
    p_recon.add_argument("--json", action="store_true", help="Output the full JSON run report")
    p_recon.set_defaults(func=cmd_reconstruct)

    # verify
    p_verify = subparsers.add_parser(
        "verify",
        help="Verify claims about a binary against the deterministic tools (the core Reverify loop)",
    )
    p_verify.add_argument("target", help="File path or hex stream to check claims against")
    p_verify.add_argument("--claim", help="A single claim as a JSON object, or a JSON array of claims")
    p_verify.add_argument("--claims-file", help="Path to a JSON file with a claim object or array")
    p_verify.add_argument("--json", action="store_true", help="Output the full JSON verdict report")
    p_verify.set_defaults(func=cmd_verify)

    # audit-boundary
    p_audit = subparsers.add_parser("audit-boundary", help="Audit filesystem path and network SSRF boundaries")
    p_audit.add_argument("--workspace", help="Target workspace path (defaults to current dir)")
    p_audit.add_argument("--urls", help="Comma-separated URLs to evaluate for SSRF / loopback filtering")
    p_audit.add_argument("--json", action="store_true", help="Output full JSON audit report")
    p_audit.set_defaults(func=cmd_audit_boundary)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
