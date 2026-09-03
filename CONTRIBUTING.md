# Contributing to Reverify

Reverify's whole point is that a claim about a binary is only trusted once it has
been checked against the actual bytes. Contributions are held to the same bar:
**a change that affects behavior comes with a test that would fail without it.**

## The one rule that matters most

The verifier must **never** mark a wrong claim `VERIFIED`. A false positive here is
worse than a missed detection, because it launders a hallucination into a
"verified" fact. If you find a case where a wrong claim slips through, that is the
most valuable bug report there is — open a **false-VERIFIED report** issue with the
bytes (or a minimal synthetic sample) and the claim, and it jumps the queue.

## How to contribute

1. Fork, branch, and make your change.
2. Add or update tests under `reverify/tests/`. Run the whole suite:
   ```bash
   cd reverify && python -m unittest discover -s tests
   ```
   Everything must stay green, with and without the optional engines installed
   (`pip install "reverify[full]"` gives you capstone/unicorn/lief).
3. For anything touching a reader (parser, disassembler, emulator), prefer a
   **differential or known-answer test** over a hand-written expectation — check
   your code against lief / capstone / Unicorn / a hand-verified vector, not
   against your own understanding. See `tests/test_differential.py` and
   `tests/test_oracle.py` for the pattern. Hand-written tests share the author's
   blind spots; cross-checks don't.
4. Keep the pure-Python fallback working: the toolkit must install and run with no
   compiled dependencies.
5. Open a PR describing what changed and how it's verified.

## Good first contributions

- Add instruction known-answer vectors to `tests/test_oracle.py`.
- Run `benchmarks/prologue_prior.py` on a new platform (Linux ELF, macOS Mach-O)
  and report the numbers.
- A new verifier claim kind, with tests, that checks something against the bytes.

## Scope and acceptable use

Reverify is for authorized reverse engineering — malware analysis, CTF,
interoperability research, and software you own or may analyze. See
[SECURITY.md](SECURITY.md). Contributions that only serve unauthorized use are out
of scope.

Discussion and questions: GitHub Discussions. Thanks for helping make AI
reverse engineering something you can check.
