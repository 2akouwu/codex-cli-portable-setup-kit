# Worked example: catching a real model's hallucination

Reverify's claim is that the deterministic tools catch a language model's mistakes
about a binary. Here is that happening, end to end, on a real Windows system
binary — with **no API key and no specific model**: the language model driving the
loop was Claude, plugged in as the `propose` callable (the proposer is
model-agnostic by design; in normal use it is whatever agent you already run,
calling the `re_verify_claim` MCP tool).

**Target:** `C:\Windows\System32\kernel32.dll` (PE32+, x86-64).
**Goal:** reconstruct the entry-point prologue and confirm some exports.

The model saw only the fact sheet (`binary_facts`): format, arch, sections,
imports, strings, entry RVA `0x2c500`. It did **not** see the entry-point
disassembly.

## Round 1 — the model proposes from priors

```
[REFUTED ] instructions @ entry (rva 0x2c500)  mnemonics ["push","mov","sub"]
           note: "DllMainCRTStartup: standard frame prologue (prior guess)"
[VERIFIED] export_present  CreateFileW
[VERIFIED] export_present  GetProcAddress
[VERIFIED] section_present .text
```

The model guessed the textbook `push rbp; mov rbp, rsp; sub rsp, N` prologue — a
strong prior from training text. It is wrong here. The verifier **refuted** it and
returned what is actually at the entry point:

```
mov qword ptr [rsp + 8], rbx ; push rdi ; sub rsp, 0x20 ; mov edi, edx ; mov rbx, rcx
```

That is the real MSVC x64 prologue (save rbx to shadow space, save rdi, allocate
stack, stash the two arguments). The model's true priors — that kernel32 exports
`CreateFileW` and `GetProcAddress` — verified.

## Round 2 — the model corrects from the evidence

```
[VERIFIED] instructions @ entry  mnemonics ["mov","push","sub","mov","mov"]
           operands ["qword ptr [rsp + 8], rbx","rdi","rsp, 0x20","edi, edx","rbx, rcx"]  mode=exact
[VERIFIED] export_present  CreateFileW
[VERIFIED] export_present  VirtualAlloc

Verified 3/3.  Information 1.236.  Trustworthy: True  Grounded: True
```

## What this shows

- **The verifier caught a genuine, prior-driven hallucination** (the canonical
  prologue) on a real binary, and handed back the bytes needed to fix it.
- **The loop is model-agnostic and needs no API key**: the model here was Claude,
  driving the same injected-`propose` interface any model uses. In normal use your
  coding agent is the proposer through MCP.
- **"Grounded" means informative**: the trivial claims that merely restate the fact
  sheet are down-weighted; the verified reconstruction carries real information.

Offsets above are specific to one Windows build; the mechanism is not.
