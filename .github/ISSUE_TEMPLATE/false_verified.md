---
name: "False VERIFIED (a wrong claim slipped through)"
about: The verifier marked a claim VERIFIED that is actually wrong. This is the most important bug type.
title: "[false-VERIFIED] "
labels: ["bug", "false-positive"]
---

**This is the bug that matters most: a hallucination that got a VERIFIED stamp.**

## The claim
```json
<paste the exact claim JSON>
```

## The binary / bytes
- Minimal sample (hex, or a synthetic builder snippet) that reproduces it:
```
<hex or code>
```
(Please do not attach real malware or copyrighted binaries — a minimal synthetic
reproduction is ideal. A public hash is fine if the sample can't be shared.)

## What reverify said vs. the truth
- reverify returned: `VERIFIED`
- The claim is actually wrong because: <explain, with the real bytes/behavior>

## Environment
- reverify version (`pip show reverify`):
- backends active (`reverify backends`):
