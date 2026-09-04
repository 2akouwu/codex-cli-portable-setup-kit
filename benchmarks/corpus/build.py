#!/usr/bin/env python3
"""Build the reproducible benchmark corpus from ``src/*.c`` with every compiler on the host.

Outputs ``build/<compiler>-<opt>-<name>.<so|dylib|dll>`` (shared libraries, so every
function is an export and therefore an independently known function start) and
``build/manifest.json`` with the toolchain version, the exact flags and the SHA-256 of each
artifact. Compilers tried: gcc, clang, cl (MSVC; needs the developer environment). Nothing
here is downloaded — the corpus is redistributable and anyone can rebuild it.

Usage:
    python benchmarks/corpus/build.py [--out DIR]
"""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")


def _version(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        text = (p.stdout or "") + (p.stderr or "")
        return text.strip().splitlines()[0] if text.strip() else "?"
    except Exception as exc:  # noqa: BLE001
        return f"? ({type(exc).__name__})"


def _run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def build(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    sources = sorted(f for f in os.listdir(SRC) if f.endswith(".c"))
    is_win, is_mac = sys.platform.startswith("win"), sys.platform == "darwin"
    ext = "dll" if is_win else ("dylib" if is_mac else "so")
    compilers = []
    for name in ("gcc", "clang"):
        if shutil.which(name):
            compilers.append((name, _version([name, "--version"])))
    if is_win and shutil.which("cl"):
        compilers.append(("cl", _version(["cl"])))
    manifest = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(), "machine": platform.machine(),
        "sources": {s: hashlib.sha256(open(os.path.join(SRC, s), "rb").read()).hexdigest() for s in sources},
        "compilers": dict(compilers), "artifacts": [], "failures": [],
    }
    for comp, _ver in compilers:
        for opt in ("O0", "O2"):
            for src in sources:
                name = src[:-2]
                out = os.path.join(out_dir, f"{comp}-{opt}-{name}.{ext}")
                if comp == "cl":
                    flags = ["/nologo", "/LD", "/Od" if opt == "O0" else "/O2", "/Zi-" if False else "/W3"]
                    cmd = ["cl"] + [f for f in flags if f] + [os.path.join(SRC, src), f"/Fe:{out}", f"/Fo:{out}.obj"]
                else:
                    flags = [f"-{opt}", "-fno-omit-frame-pointer" if opt == "O0" else "-fomit-frame-pointer",
                             "-fPIC", "-dynamiclib" if is_mac else "-shared", "-fcf-protection=none"]
                    cmd = [comp] + flags + ["-o", out, os.path.join(SRC, src)]
                rc, log = _run(cmd, HERE)
                if rc != 0 and "-fcf-protection=none" in cmd:
                    cmd = [c for c in cmd if c != "-fcf-protection=none"]   # older compilers / other arches
                    rc, log = _run(cmd, HERE)
                if rc != 0 or not os.path.exists(out):
                    manifest["failures"].append({"compiler": comp, "opt": opt, "source": src, "log": log[-400:]})
                    continue
                with open(out, "rb") as f:
                    data = f.read()
                manifest["artifacts"].append({
                    "file": os.path.basename(out), "compiler": comp, "opt": opt, "source": src,
                    "flags": " ".join(cmd[1:-2] if comp != "cl" else cmd[1:]), "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                })
    for junk in os.listdir(out_dir):
        if junk.endswith((".obj", ".exp", ".lib", ".pdb", ".ilk")):
            os.remove(os.path.join(out_dir, junk))
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    return manifest


def main(argv):
    out = os.path.join(HERE, "build")
    if "--out" in argv:
        out = argv[argv.index("--out") + 1]
    m = build(out)
    print(f"compilers: {m['compilers'] or 'none found'}")
    print(f"built {len(m['artifacts'])} artifacts into {out}; failures: {len(m['failures'])}")
    for a in m["artifacts"]:
        print(f"  {a['file']:36} {a['size']:>8}  {a['sha256'][:12]}")
    for fl in m["failures"][:5]:
        print(f"  FAILED {fl['compiler']} {fl['opt']} {fl['source']}: {fl['log'][-200:].strip()}")
    return 0 if m["artifacts"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
