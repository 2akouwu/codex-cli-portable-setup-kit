<h1 align="center">Reverify</h1>

<p align="center">
  <strong>Reverse engineering you can trust.</strong><br>
  An AI-assisted RE toolkit whose findings are checked against the binary — not hallucinated.
</p>

<p align="center">
  <a href="https://app.ona.com/#https://github.com/2akouwu/reverify">
    <img src="https://ona.com/build-with-ona.svg" alt="Build with Ona" />
  </a>
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

- **Deterministic core** — PE/ELF/Mach-O parsing, x86/x64/ARM/ARM64 disassembly, AOB pattern
  scanning, CPU emulation, Protobuf/TLV dissection, Frida hook generation. Pure Python out of
  the box; installs clean with no Ghidra.
- **Mature engines, optional** — with `pip install "reverify[full]"` the toolkit upgrades
  itself in place to **capstone** (disassembly), **unicorn** (real CPU emulation) and **lief**
  (PE/ELF/Mach-O). Not installed? It falls back to the pure-Python core. `reverify backends`
  shows what's active.
- **Grounded, not guessed** — structural claims are verified against the binary by the tools.
- **Agent-native** — ships as an MCP server, so Claude Code, Cursor, and other agents can call
  the tools directly; also a plain CLI.

> Reverify is for **authorized** reverse engineering — malware analysis, CTF, interoperability
> research, and software you own or are permitted to analyze. See [SECURITY.md](SECURITY.md).

## Quick start

```bash
# Install the CLI + MCP server from PyPI:
pip install reverify        # pure-Python core; or "reverify[full]" for capstone+unicorn+lief
reverify auto sample.bin --json

# Or run straight from a checkout — pure standard library, nothing to install:
python reverify/cli.py auto sample.bin --json
python reverify/cli.py parse-pe sample.exe --json
python reverify/cli.py disasm 90505831C0C3 --arch x86_64
```

## The verification loop

This is what the name is about. A **claim** is any hypothesis about the binary; the
deterministic tools are the judge and hand back `VERIFIED`, `REFUTED`, or
`INCONCLUSIVE` together with the bytes they actually observed:

```bash
reverify verify sample.bin --claim '{
  "kind": "instructions", "offset": 4096,
  "mnemonics": ["push", "mov", "sub"], "note": "function prologue"
}'
```

```bash
# Check a reconstructed routine actually computes what the model claimed:
reverify verify - --claim '{
  "kind": "emulate_result", "code": "b805000000b90300000001c8c3",
  "arch": "x86", "expect_registers": {"eax": 8}
}'
```

Claims can be batched from a JSON file (`--claims-file claims.json`); the CLI exits
non-zero if **anything** is refuted, so an agent or CI job can gate on a grounded
reconstruction. Claim kinds: `bytes_at`, `u16_at` / `u32_at` / `u64_at` (typed reads, no
endianness math), `pattern_present`, `string_present`, `instructions` (mnemonics and
optionally operands), `emulate_result`, `protobuf_field`, `import_present`,
`export_present`, `section_present`. Offsets are file offsets unless a claim says
`"space": "rva"` or `"va"`; the verifier translates through the section table and echoes
all three addresses in the evidence, and a refuted `bytes_at` reports where the expected
bytes actually are. Set `"observe": true` (or omit `expected`) to have the tools *read* a
value instead of asserting one, and `"depends_on": [...]` so a refuted root invalidates
the claims built on it.

### Grounded means *informative*, not just "nothing refuted"

"Every claim verified" is trivially reachable: assert that the file starts with `MZ` and
that `.text` exists. So Reverify also weighs how much a verified set actually says. Each
result carries a `weight` — zero for claims that merely restate the fact sheet the model was
shown, for duplicates, for inline code/data that does not occur in the binary
(self-referential), and for echoes of the tools' own previous output; otherwise it is
**measured from the binary itself** — how often the expected content occurs in this file and
how much entropy it has — so zero padding, a ubiquitous prologue, or a pattern that matches
everywhere weigh almost nothing even though they verify, and emulation must actually execute
non-degenerate code. A reconstruction is **grounded** only when nothing
is refuted *and* the verified weight reaches `--min-information` (default 1.0). This follows
the CORE refinement of FActScore: credit only claims that are factual, informative and
non-repetitive. `reverify reconstruct --samples N` draws several proposals per round and
lets the verifier — not the model's confidence — select among them.

## The toolkit

| Command | What it does |
|---|---|
| `reconstruct` | **Closed loop: a model proposes claims, the tools verify, iterate until grounded** |
| `verify` | **Check a claim about the binary against the tools — VERIFIED / REFUTED / INCONCLUSIVE** |
| `auto` | Auto-triage: detect format, architecture, sections, top strings |
| `parse` | PE / ELF / Mach-O: arch, entry, sections, imports, exports (lief when installed) |
| `parse-pe` | PE32/PE32+ headers, imports, exports |
| `backends` | Show which engines are active (capstone / unicorn / lief) |
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
directly — with the deterministic tools as ground truth. The `re_verify_claim` tool exposes
the verification loop, so an agent can have its own hypotheses judged against the bytes
before it reports them.

## Status

**v0.4.0 — a loop that is hard to game**, on [PyPI](https://pypi.org/project/reverify/)
(`pip install reverify`). The tool-grounded judge — a claim about the binary is checked
against the actual bytes and returned as `VERIFIED` / `REFUTED` / `INCONCLUSIVE` /
`OBSERVED` / `INVALIDATED` with evidence — ships as `reverify verify` and the
`re_verify_claim` MCP tool, and `reverify reconstruct` closes the loop (a model proposes, the
tools judge, it iterates until grounded). v0.3.0 brought the mature engines (capstone,
unicorn, lief; pure-Python fallback). v0.4.0 hardens the loop against the ways a model games
a verifier: information-weighted scoring, address spaces and typed reads, observe-then-assert,
dependencies, echo and attrition detection, and distribution-shift signals in the fact sheet.
Tested with 133 unit tests.

## License

MIT — see [LICENSE](LICENSE).
