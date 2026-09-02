<h1 align="center">Reverify</h1>

<p align="center">
  <strong>Reverse engineering you can trust.</strong><br>
  An AI-assisted RE toolkit whose findings are checked against the binary — not hallucinated.
</p>

## The problem

Language models are great at reading code and unreliable at reverse engineering. Ask a
model to reconstruct a struct or an algorithm from a binary and it will confidently invent
offsets, sizes, and behavior. In binary analysis this hallucination problem is far worse
than in source code, and *"did the model just make that up?"* is the single biggest blocker
to using AI for real RE.

## What Reverify does

Reverify pairs a language model with a **deterministic, pure-Python RE toolkit** and makes the
toolkit the judge. The model proposes; the tools verify. A hypothesis about a structure or an
algorithm is only reported once it has been **checked against the actual bytes** — disassembled,
pattern-matched, or executed in the emulator — so the output is grounded in the binary instead
of the model's imagination.

- **Deterministic core** — PE32/PE32+ parsing, x86/x64 disassembly, AOB pattern scanning,
  CPU micro-emulation, Protobuf/TLV dissection, Frida hook generation. Pure Python, no Ghidra,
  no heavy install.
- **Grounded, not guessed** — structural claims are verified against the binary by the tools.
- **Agent-native** — ships as an MCP server, so Claude Code, Cursor, and other agents can call
  the tools directly; also a plain CLI.

> Reverify is for **authorized** reverse engineering — malware analysis, CTF, interoperability
> research, and software you own or are permitted to analyze. See [SECURITY.md](SECURITY.md).

## Quick start

```bash
python reverify/cli.py auto sample.bin --json
python reverify/cli.py parse-pe sample.exe --json
python reverify/cli.py disasm 90505831C0C3 --arch x86_64
```

## The toolkit

| Command | What it does |
|---|---|
| `auto` | Auto-triage: detect format, architecture, sections, top strings |
| `parse-pe` | PE32/PE32+ headers, imports, exports |
| `disasm` | x86/x64 disassembly of hex or a section |
| `pattern-scan` | AOB scan with `??` wildcards |
| `strings` | ASCII + UTF-16LE extraction with offsets |
| `emulate` | CPU register/stack micro-emulation |
| `decode-protobuf` / `decode-tlv` | schema-less wire-format dissection |
| `gen-hook` | Frida interceptor script generation |
| `hexdump` | aligned hex dump |
| `diff-patch` | binary diff / patch generation |
| `audit-boundary` | defensive filesystem/SSRF boundary audit |

## MCP server

Reverify exposes the toolkit to AI agents over the Model Context Protocol:

```bash
python reverify/mcp_server.py
```

Point Claude Code or Cursor at it and the agent can parse, disassemble, and scan binaries
directly — with the deterministic tools as ground truth.

## Status

**v0.0.0 — groundwork.** The deterministic toolkit, CLI, and MCP server are here and tested
(42 unit tests). The tool-grounded verification loop — model proposes, tools verify, iterate
until the reconstruction matches the binary — is the next milestone.

## License

MIT — see [LICENSE](LICENSE).
