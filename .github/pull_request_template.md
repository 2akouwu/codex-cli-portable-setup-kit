## What this changes
<one or two sentences>

## How it's verified
<which tests you added/updated; for reader changes, which cross-check (lief /
capstone / Unicorn / known-answer vector) backs it — not just a hand-written
expectation>

## Checklist
- [ ] `cd reverify && python -m unittest discover -s tests` is green
- [ ] Passes with and without the optional engines (`pip install "reverify[full]"`)
- [ ] The pure-Python fallback still installs and runs
- [ ] No change makes the verifier accept a claim the bytes don't support
