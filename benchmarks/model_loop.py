#!/usr/bin/env python3
"""Closed-loop benchmark with a real model (opt-in: needs an OpenAI-compatible endpoint).

The other benchmarks need no model. This one measures what happens when a language model
is actually in the loop: for each binary, ``ReconstructionAgent`` asks the model for
checkable claims, the verifier judges them, refutations are fed back, and the run ends
grounded or at the round cap. Recorded per binary: whether the reconstruction grounded,
rounds used, information reached, and how many claims were refuted (hallucinations caught),
echoed, trivial or already known (restatements rejected). Totals give the grounded rate and
the mean number of hallucinations caught per binary.

No ground truth beyond the verifier is needed, because the verifier is the ground truth —
its own soundness is measured by ``verifier_matrix.py`` and the test suite. What this adds
is the *model-facing* number: how often a real model's first proposals are wrong, and
whether the loop recovers.

Any endpoint works: set ``OPENAI_API_KEY`` (and ``OPENAI_BASE_URL`` / ``OPENAI_MODEL`` for
a non-OpenAI server). ``--mock`` runs the offline demo proposer to check the plumbing.

Usage:
    python benchmarks/model_loop.py [dir ...] [--per-dir N] [--rounds R] [--mock]
                                    [--json OUT] [--markdown]
"""

import hashlib
import json
import os
import platform
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from reverify import __version__  # noqa: E402
from reverify.agent import ReconstructionAgent, openai_proposer, demo_proposer  # noqa: E402
from reverify.backends import backend_report  # noqa: E402
from reverify.binary import parse_binary  # noqa: E402
from prologue_prior import default_dirs, corpus  # noqa: E402

GOAL = ("Establish checkable facts about this binary: the instructions at the entry point, "
        "one import it uses, one export or section, and one typed value read from the headers. "
        "Prefer specific, falsifiable claims.")


def run(dirs, per_dir=5, rounds=3, mock=False, model=None):
    dirs = dirs or default_dirs()
    rows = []
    t0 = time.time()
    for path in corpus(dirs, per_dir):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        info = parse_binary(data)
        if info.format not in ("PE", "ELF", "MachO") or info.error:
            continue
        propose = demo_proposer(data) if mock else openai_proposer(model=model)
        started = time.time()
        try:
            res = ReconstructionAgent(data, propose, max_rounds=rounds).run(GOAL)
        except Exception as exc:  # endpoint errors are recorded, not fatal
            rows.append({"file": os.path.basename(path), "sha256": hashlib.sha256(data).hexdigest(),
                         "error": f"{type(exc).__name__}: {str(exc)[:160]}"})
            continue
        hist = res["history"]
        agg = {"claims": 0, "verified": 0, "refuted": 0, "inconclusive": 0, "trivial": 0, "echoed": 0, "known": 0}
        for h in hist:
            rep = h["report"]
            agg["claims"] += rep["total_claims"]
            agg["verified"] += rep["verified"]
            agg["refuted"] += rep["refuted"]
            agg["inconclusive"] += rep["inconclusive"]
            agg["trivial"] += rep["trivial_verified"]
            agg["echoed"] += h.get("echoed", 0)
            agg["known"] += h.get("known", 0)
        rows.append({
            "file": os.path.basename(path), "sha256": hashlib.sha256(data).hexdigest(), "format": info.format,
            "arch": info.arch, "grounded": res["grounded"], "rounds": res["rounds_used"],
            "information": res["information"], "round1_refuted": hist[0]["report"]["refuted"] if hist else None,
            "round1_claims": hist[0]["report"]["total_claims"] if hist else None, **agg,
            "seconds": round(time.time() - started, 1),
        })
    ok = [r for r in rows if "error" not in r]
    n = len(ok)
    totals = {
        "binaries": n, "errors": len(rows) - n,
        "grounded": sum(1 for r in ok if r["grounded"]),
        "grounded_rate": (sum(1 for r in ok if r["grounded"]) / n) if n else None,
        "mean_rounds": (sum(r["rounds"] for r in ok) / n) if n else None,
        "claims": sum(r["claims"] for r in ok),
        "refuted_total": sum(r["refuted"] for r in ok),
        "round1_hallucination_rate": (sum(r["round1_refuted"] or 0 for r in ok) / max(1, sum(r["round1_claims"] or 0 for r in ok))) if n else None,
        "restatements_rejected": sum(r["trivial"] + r["echoed"] + r["known"] for r in ok),
        "seconds": round(time.time() - t0, 1),
    }
    engines = {k: v for k, v in backend_report().items() if k != "install_hint"}
    return {
        "schema": 1, "benchmark": "model_loop",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": "mock (offline demo proposer)" if mock else (model or os.getenv("OPENAI_MODEL") or "gpt-4o"),
        "endpoint": None if mock else (os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1"),
        "goal": GOAL, "rounds_cap": rounds,
        "environment": {"reverify": __version__, "python": platform.python_version(),
                        "platform": platform.platform(), "engines": engines},
        "corpus": {"dirs": dirs, "per_dir": per_dir},
        "rows": rows, "totals": totals,
    }


def markdown(result):
    t = result["totals"]
    lines = [
        f"### model_loop — model `{result['model']}`, {t['binaries']} binaries, rounds cap {result['rounds_cap']}, "
        f"reverify {result['environment']['reverify']}",
        "",
        "| metric | value |",
        "|---|---|",
        f"| grounded | {t['grounded']}/{t['binaries']} |",
        f"| mean rounds | {t['mean_rounds'] if t['mean_rounds'] is None else round(t['mean_rounds'], 2)} |",
        f"| round-1 claims refuted (model hallucinations caught) | {100 * (t['round1_hallucination_rate'] or 0):.0f}% |",
        f"| claims refuted in total | {t['refuted_total']} of {t['claims']} |",
        f"| restatements rejected (trivial + echo + known) | {t['restatements_rejected']} |",
        f"| endpoint errors | {t['errors']} |",
        "",
        "| binary | grounded | rounds | info | r1 refuted/claims | refuted | rejected |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in result["rows"]:
        if "error" in r:
            lines.append(f"| {r['file']} | error | | | | | {r['error'][:60]} |")
        else:
            lines.append(f"| {r['file']} | {'yes' if r['grounded'] else 'no'} | {r['rounds']} | {r['information']} | "
                         f"{r['round1_refuted']}/{r['round1_claims']} | {r['refuted']} | {r['trivial'] + r['echoed'] + r['known']} |")
    return "\n".join(lines)


def main(argv):
    per, rounds, mock, out_json, want_md, model, args = 5, 3, False, None, False, None, []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--per-dir":
            per = int(argv[i + 1]); i += 2; continue
        if a == "--rounds":
            rounds = int(argv[i + 1]); i += 2; continue
        if a == "--model":
            model = argv[i + 1]; i += 2; continue
        if a == "--json":
            out_json = argv[i + 1]; i += 2; continue
        if a == "--markdown":
            want_md = True; i += 1; continue
        if a == "--mock":
            mock = True; i += 1; continue
        args.append(a); i += 1
    if not mock and not os.getenv("OPENAI_API_KEY"):
        print("model_loop needs OPENAI_API_KEY (any OpenAI-compatible endpoint via OPENAI_BASE_URL), or --mock", file=sys.stderr)
        return 3
    result = run(args, per, rounds, mock, model)
    print(markdown(result) if want_md else json.dumps(result["totals"], indent=1))
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=1)
        print(f"\nwrote {out_json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
