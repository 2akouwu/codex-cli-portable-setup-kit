#!/usr/bin/env python3
"""Semantic layer: function boundaries, call graph and cross-references from a real engine.

Bytes, instructions, imports and emulation are what the deterministic core can
judge on its own. The claims analysts actually make — *function X calls Y*,
*this string is referenced from that routine*, *this code is reachable from the
entry point* — need function boundaries and cross-references, which means a
program-analysis engine. Reverify does not build one. It stands on **angr**
(``CFGFast``) and keeps its own part thin: an engine-neutral
:class:`SemanticView` (functions, call edges, xrefs, reachability) that the
verifier's ``function_at`` / ``calls`` / ``references`` /
``reachable_from_entry`` claims are checked against.

Honesty about strength: a recovered control-flow graph is *analysis-derived*.
CFGFast is heuristic — it can miss functions reached only through indirect
jumps, or split and merge them — so semantic verdicts are recorded at the
``DERIVED`` tier below ``VERIFIED``, and every piece of evidence names the
engine and its version. Without an engine the pure-Python fallback only knows
what is independently certain (the entry point and the exports are function
starts) and answers ``INCONCLUSIVE`` for everything else — never a guess.

All addresses in the view are RVAs (relative to the image base), the same
space the rest of Reverify translates to through the section table.
"""

from __future__ import annotations

import bisect
import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:  # package import
    from .binary import parse_binary, BinaryInfo
    from .backends import HAS_ANGR, ANGR_VERSION
except ImportError:  # flat import (CLI / tests)
    from binary import parse_binary, BinaryInfo
    from backends import HAS_ANGR, ANGR_VERSION

SEMANTIC_KINDS = ("function_at", "calls", "references", "reachable_from_entry")
INSTALL_HINT = 'pip install "reverify[angr]"'


@dataclass
class Function:
    rva: int
    name: str
    size: int = 0
    blocks: int = 0
    is_import: bool = False   # a stub standing for an imported function (extern / PLT)
    is_export: bool = False
    returning: Optional[bool] = None
    callees: List[int] = field(default_factory=list)
    callers: List[int] = field(default_factory=list)

    def brief(self, view: "SemanticView") -> Dict[str, Any]:
        out: Dict[str, Any] = {"name": self.name, "rva": hex(self.rva)}
        if view.image_base is not None and not self.is_import:
            out["va"] = hex(view.image_base + self.rva)
        if self.is_import:
            out["import"] = True
        return out

    def describe(self, view: "SemanticView") -> Dict[str, Any]:
        out = self.brief(view)
        out.update({"size": self.size, "blocks": self.blocks, "is_export": self.is_export})
        if self.returning is not None:
            out["returning"] = self.returning
        callees = [view.functions[c].name for c in self.callees[:12] if c in view.functions]
        if callees:
            out["callees_sample"] = callees
        return out


@dataclass
class SemanticView:
    engine: str
    version: Optional[str]
    image_base: Optional[int]
    entry_rva: Optional[int]
    complete: bool                                   # False: only entry/exports are known
    functions: Dict[int, Function] = field(default_factory=dict)
    edges: Set[Tuple[int, int]] = field(default_factory=set)
    xrefs: Dict[int, List[Dict[str, Any]]] = field(default_factory=dict)
    reachable: Set[int] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)
    _blocks: List[Tuple[int, int, int]] = field(default_factory=list)   # (start, end, function rva)
    _starts: List[int] = field(default_factory=list)
    _by_name: Dict[str, int] = field(default_factory=dict)

    # -- indexing --------------------------------------------------------------

    def finalize(self) -> "SemanticView":
        self._starts = sorted(self.functions)
        self._blocks.sort()
        self._by_name = {}
        for rva, f in self.functions.items():
            self._by_name.setdefault(f.name, rva)
            self._by_name.setdefault(f.name.lower(), rva)
        for a, b in self.edges:
            if a in self.functions and b in self.functions:
                self.functions[a].callees.append(b)
                self.functions[b].callers.append(a)
        for f in self.functions.values():
            f.callees = sorted(set(f.callees))
            f.callers = sorted(set(f.callers))
        return self

    # -- queries ---------------------------------------------------------------

    def function_at(self, rva: int) -> Optional[Function]:
        return self.functions.get(rva)

    def function_containing(self, rva: int) -> Optional[Function]:
        f = self.functions.get(rva)
        if f is not None:
            return f
        i = bisect.bisect_right(self._blocks, (rva, 1 << 62, 1 << 62)) - 1
        while i >= 0:
            start, end, frva = self._blocks[i]
            if start <= rva < end:
                return self.functions.get(frva)
            if end <= rva and start <= rva - 65536:
                break
            i -= 1
        return None

    def nearest_function_start(self, rva: int) -> Optional[Tuple[Function, int]]:
        if not self._starts:
            return None
        i = bisect.bisect_left(self._starts, rva)
        best = None
        for j in (i - 1, i):
            if 0 <= j < len(self._starts):
                cand = self._starts[j]
                f = self.functions[cand]
                if f.is_import:
                    continue
                d = cand - rva
                if best is None or abs(d) < abs(best[1]):
                    best = (f, d)
        return best

    def resolve_name(self, name: str) -> Optional[int]:
        n = str(name).strip()
        for key in (n, n.lower()):
            if key in self._by_name:
                return self._by_name[key]
        # "lib!func" -> "func"
        if "!" in n:
            return self.resolve_name(n.split("!", 1)[1])
        return None

    def callees_of(self, rva: int) -> List[Function]:
        f = self.functions.get(rva)
        return [self.functions[c] for c in (f.callees if f else []) if c in self.functions]

    def callers_of(self, rva: int) -> List[Function]:
        f = self.functions.get(rva)
        return [self.functions[c] for c in (f.callers if f else []) if c in self.functions]

    def references_to(self, rva: int) -> List[Dict[str, Any]]:
        return list(self.xrefs.get(rva, []))

    def names_sample(self, limit: int = 32) -> List[str]:
        return [f.name for f in list(self.functions.values())[:limit]]

    def summary(self) -> Dict[str, Any]:
        n_imports = sum(1 for f in self.functions.values() if f.is_import)
        return {
            "engine": self.engine,
            "engine_version": self.version,
            "complete": self.complete,
            "functions": len(self.functions) - n_imports,
            "import_stubs": n_imports,
            "call_edges": len(self.edges),
            "xref_targets": len(self.xrefs),
            "entry_rva": hex(self.entry_rva) if self.entry_rva is not None else None,
            "reachable_from_entry": len(self.reachable),
            "notes": list(self.notes),
            "install_hint": None if self.complete else INSTALL_HINT,
        }

    def list_functions(self, limit: int = 200, imports: bool = False) -> List[Dict[str, Any]]:
        out = []
        for rva in self._starts:
            f = self.functions[rva]
            if f.is_import and not imports:
                continue
            out.append(f.describe(self))
            if len(out) >= limit:
                break
        return out


# -- builders -----------------------------------------------------------------

_CACHE: Dict[str, SemanticView] = {}


def _pure_view(data: bytes, info: Optional[BinaryInfo] = None, notes: Optional[List[str]] = None) -> SemanticView:
    """What is certain without an engine: the entry point and the exports start functions."""
    info = info or parse_binary(data)
    view = SemanticView(engine="pure-python", version=None, image_base=info.image_base,
                        entry_rva=None, complete=False, notes=list(notes or []))
    if info.format == "raw" or info.error:
        view.notes.append("not a parseable binary")
        return view.finalize()
    entry = info.entrypoint
    if entry is not None and info.format == "ELF" and info.image_base is not None:
        entry = entry - info.image_base
    if entry is not None:
        view.entry_rva = entry
        view.functions[entry] = Function(entry, "entry", is_export=False)
    for name, rva in (info.export_rvas or {}).items():
        if rva in view.functions and view.functions[rva].name == "entry":
            view.functions[rva].name = name
        view.functions.setdefault(rva, Function(rva, name, is_export=True))
        view.functions[rva].is_export = True
    view.notes.append(f"pure fallback: only the entry point and {len(info.export_rvas or {})} exports are known as function starts; {INSTALL_HINT} for boundaries, calls and xrefs")
    return view.finalize()


def _angr_view(data: bytes, sha: str) -> SemanticView:
    import logging
    for name in ("angr", "cle", "pyvex", "claripy", "ailment"):
        logging.getLogger(name).setLevel(logging.ERROR)
    import angr  # noqa: F401
    import networkx as nx

    path = os.path.join(tempfile.gettempdir(), f"reverify-{sha[:24]}.bin")
    if not os.path.exists(path) or os.path.getsize(path) != len(data):
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)

    info = parse_binary(data)
    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True, show_progressbar=False)
    mo = proj.loader.main_object
    base = int(mo.mapped_base)
    ext = proj.loader.extern_object
    ext_range = (int(ext.min_addr), int(ext.max_addr)) if ext is not None else None
    exports = set(info.exports)

    view = SemanticView(engine="angr", version=ANGR_VERSION, image_base=info.image_base if info.image_base is not None else base,
                        entry_rva=int(proj.entry) - base, complete=True)
    for f in proj.kb.functions.values():
        addr = int(f.addr)
        is_import = bool(getattr(f, "is_simprocedure", False) or getattr(f, "is_plt", False)
                         or (ext_range and ext_range[0] <= addr <= ext_range[1]))
        fn = Function(addr - base, str(f.name), size=int(getattr(f, "size", 0) or 0),
                      blocks=len(getattr(f, "block_addrs_set", ()) or ()), is_import=is_import,
                      is_export=str(f.name) in exports, returning=getattr(f, "returning", None))
        view.functions[fn.rva] = fn
        if not is_import:
            for baddr in getattr(f, "block_addrs_set", ()) or ():
                node = cfg.model.get_any_node(baddr)
                size = int(getattr(node, "size", 0) or 0) if node is not None else 0
                if size > 0:
                    view._blocks.append((int(baddr) - base, int(baddr) - base + size, fn.rva))
    for a, b in proj.kb.callgraph.edges():
        view.edges.add((int(a) - base, int(b) - base))

    type_name = {}
    try:
        from angr.knowledge_plugins.xrefs.xref_types import XRefType
        type_name = {getattr(XRefType, n): n.lower() for n in dir(XRefType) if n[:1].isupper() and isinstance(getattr(XRefType, n), int)}
    except Exception:
        pass
    for dst, refs in proj.kb.xrefs.xrefs_by_dst.items():
        entries = []
        for r in refs:
            node = cfg.model.get_any_node(getattr(r, "block_addr", None)) if getattr(r, "block_addr", None) is not None else None
            frva = (int(node.function_address) - base) if node is not None and node.function_address is not None else None
            fname = view.functions[frva].name if frva in view.functions else None
            entries.append({
                "function": fname,
                "function_rva": frva,
                "from_rva": (int(r.ins_addr) - base) if getattr(r, "ins_addr", None) is not None else None,
                "type": type_name.get(getattr(r, "type", None), str(getattr(r, "type", "?"))),
                "data": getattr(getattr(r, "memory_data", None), "sort", None),
            })
        view.xrefs[int(dst) - base] = entries

    ef = proj.kb.functions.get(proj.entry) if proj.entry is not None else None
    if ef is not None:
        try:
            reach = nx.descendants(proj.kb.callgraph, ef.addr) | {ef.addr}
        except Exception:
            reach = {ef.addr}
        view.reachable = {int(a) - base for a in reach}
    return view.finalize()


def semantic_view(data: bytes, prefer: Optional[str] = None) -> SemanticView:
    """The semantic view of ``data``: angr when installed, the pure fallback otherwise.

    ``prefer="pure"`` forces the fallback (tests). Views are cached per process
    by content hash, so a long-lived MCP server pays for the CFG once.
    """
    sha = hashlib.sha256(data).hexdigest()
    key = f"{sha}:{prefer or 'auto'}"
    if key in _CACHE:
        return _CACHE[key]
    view: Optional[SemanticView] = None
    notes: List[str] = []
    if prefer != "pure" and HAS_ANGR:
        try:
            view = _angr_view(data, sha)
        except Exception as exc:  # engine failure must never take the verifier down
            notes.append(f"angr failed: {type(exc).__name__}: {str(exc)[:160]}")
    if view is None:
        view = _pure_view(data, notes=notes)
    _CACHE[key] = view
    return view
