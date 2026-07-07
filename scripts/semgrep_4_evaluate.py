"""
Semgrep stage 4 — ontology EP/HP/mismatch with localization regimes.

Unit of evaluation: (cve_id, file). Reference label: the CVE's NVD cwe_ids (multi-
label). A Semgrep finding is tagged by where it falls in the vulnerable file:
  in_hunk    -> its [start,end] overlaps a before-side diff hunk
  in_context -> overlaps a hunk +/- CONTEXT lines (but not the hunk itself)
  elsewhere  -> neither
We then report EP/HP/mismatch at three regimes so localization robustness is
visible instead of silently filtered:
  whole-file  : every finding counts          (comparable to the submitted paper)
  hunk_ctx    : in_hunk OR in_context findings
  hunk_strict : in_hunk findings only

Inputs : semgrep_findings.csv, scan_manifest.csv, hunk_ranges.csv,
         security_patches_linked.csv, named_graphs_cwe.trig
Outputs: consistency_units.csv (verdict per regime), supported_ep_hp.csv (EP u HP),
         finding_localization.csv (per finding x unit, deduped to strongest rank)
"""

import re
import os
import csv
import logging
import argparse
from pathlib import Path
from collections import defaultdict, deque

import pandas as pd
from rdflib import Dataset, URIRef

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

#FINDINGS, MANIFEST, HUNKS = "semgrep_findings.csv", "scan_manifest.csv", "hunk_ranges.csv"
#CORPUS, TRIG = "security_patches_linked.csv", "named_graphs_cwe.trig"

BASE = Path(__file__).resolve().parents[1]

FINDINGS = "semgrep_findings.csv"
MANIFEST = BASE / "corpus" / "scan_manifest.csv"
HUNKS = BASE / "corpus" / "hunk_ranges.csv"
CORPUS = BASE / "inputs" / "security_patches_linked.csv"
TRIG = BASE / "inputs" / "named_graphs_cwe.trig"

OUT_UNITS, OUT_SUPPORTED, OUT_LOC = "consistency_units.csv", "supported_ep_hp.csv", "finding_localization.csv"

CHILD_OF = URIRef("http://schema.org/child_of")
ONLY_REAL_CWE, CONFIDENCE_KEEP = True, ("high", "medium")
REGIMES = {"whole_file": {"in_hunk", "in_context", "elsewhere"},
           "hunk_ctx":   {"in_hunk", "in_context"},
           "hunk_strict": {"in_hunk"}}
RANK = {"in_hunk": 3, "in_context": 2, "elsewhere": 1}


def num(cwe):
    if not isinstance(cwe, str):
        return None
    m = re.search(r"(\d+)", cwe)
    return m.group(1) if m else None


def load_hierarchy(path):
    ds = Dataset(); ds.parse(path, format="trig")
    parents, children = defaultdict(set), defaultdict(set)
    for s, _p, o, _c in ds.quads((None, CHILD_OF, None, None)):
        parents[s.split("/")[-1]].add(o.split("/")[-1])
        children[o.split("/")[-1]].add(s.split("/")[-1])
    logging.info(f"Ontology: {len(parents)} child->parent nodes")
    return parents, children


def transitive(start, adj):
    seen, q = set(), deque([start])
    while q:
        for nb in adj.get(q.popleft(), ()):
            if nb not in seen:
                seen.add(nb); q.append(nb)
    return seen


def overlaps(s, e, rs, re_):
    return s <= re_ and e >= rs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", default=".", help="folder with semgrep_findings.csv + outputs")
    args = ap.parse_args()
    run = Path(args.run_dir)
    out_units, out_supported, out_loc = (run / OUT_UNITS, run / OUT_SUPPORTED, run / OUT_LOC)

    csv.field_size_limit(2147483647)
    findings = pd.read_csv(run / FINDINGS, engine="python")
    manifest = pd.read_csv(MANIFEST, engine="python")
    hunks = pd.read_csv(HUNKS, engine="python") if os.path.exists(HUNKS) else pd.DataFrame()
    corpus = pd.read_csv(CORPUS, engine="python")
    parents, children = load_hierarchy(TRIG)

    if ONLY_REAL_CWE and "has_real_cwe" in corpus.columns:
        corpus = corpus[corpus["has_real_cwe"] == True].copy()
    if "confidence" in corpus.columns:
        corpus = corpus[corpus["confidence"].isin(CONFIDENCE_KEEP)].copy()

    kc = ["repo", "parent_sha", "filename"]
    mkey = manifest.set_index(kc)["file_key"].to_dict()
    units = (corpus.dropna(subset=kc).drop_duplicates(["cve_id"] + kc)
                   [["cve_id", "cwe_ids"] + kc].copy())
    units["file_key"] = units.apply(lambda r: mkey.get((r.repo, r.parent_sha, r.filename)), axis=1)
    units = units.dropna(subset=["file_key"]).copy()

    # findings per file_key
    fmap = defaultdict(list)
    for f in findings.itertuples(index=False):
        n = num(getattr(f, "semgrep_cwe", None))
        if n and pd.notna(f.start_line):
            fmap[f.file_key].append((int(f.start_line),
                                     int(f.end_line) if pd.notna(f.end_line) else int(f.start_line),
                                     n, f.rule_id))

    # hunk intervals per (file_key, cve_id): strict (before-side) and context
    strict_iv, ctx_iv = defaultdict(list), defaultdict(list)
    if not hunks.empty:
        for h in hunks.itertuples(index=False):
            if str(getattr(h, "added_only", "")).strip().lower() in ("1", "true", "yes"):
                continue                                 # no before-side code
            k = (h.file_key, h.cve_id)
            strict_iv[k].append((int(h.before_start), int(h.before_end)))
            if pd.notna(h.ctx_end):
                ctx_iv[k].append((int(h.ctx_start), int(h.ctx_end)))

    def localize(s, e, fk, cve):
        if any(overlaps(s, e, a, b) for a, b in strict_iv.get((fk, cve), [])):
            return "in_hunk"
        if any(overlaps(s, e, a, b) for a, b in ctx_iv.get((fk, cve), [])):
            return "in_context"
        return "elsewhere"

    rel_cache = {}
    def related(n):
        if n not in rel_cache:
            rel_cache[n] = transitive(n, parents) | transitive(n, children)
        return rel_cache[n]

    def match(found_n, gt):
        if found_n in gt:
            return "EP"
        return "HP" if related(found_n) & gt else "mismatch"

    # per finding x unit, strongest localization (dedup overlapping hunks)
    loc_rows, by_unit = [], defaultdict(list)
    for u in units.itertuples(index=False):
        gt = {num(c) for c in str(u.cwe_ids).split(";") if num(c)}
        for (s, e, fn, rule) in fmap.get(u.file_key, []):
            loc = localize(s, e, u.file_key, u.cve_id)
            m = match(fn, gt)
            by_unit[(u.cve_id, u.file_key)].append((loc, m))
            loc_rows.append({"cve_id": u.cve_id, "file_key": u.file_key, "rule_id": rule,
                             "found_cwe": fn, "start_line": s, "end_line": e,
                             "localization": loc, "match": m})
    loc_df = (pd.DataFrame(loc_rows)
              .sort_values("localization", key=lambda s: s.map(RANK), ascending=False)
              .drop_duplicates(["cve_id", "file_key", "found_cwe", "rule_id", "start_line", "end_line"]))
    loc_df.to_csv(out_loc, index=False)

    def verdict(pairs, allowed):
        cand = [m for loc, m in pairs if loc in allowed]
        if not cand:
            return "no_finding"
        if "EP" in cand:
            return "EP"
        return "HP" if "HP" in cand else "mismatch"

    out = []
    for u in units.itertuples(index=False):
        pairs = by_unit.get((u.cve_id, u.file_key), [])
        gt = {num(c) for c in str(u.cwe_ids).split(";") if num(c)}
        row = {"cve_id": u.cve_id, "repo": u.repo, "filename": u.filename,
               "parent_sha": u.parent_sha, "file_key": u.file_key,
               "reference_cwes": ";".join(sorted(gt))}
        for name, allowed in REGIMES.items():
            row[f"verdict_{name}"] = verdict(pairs, allowed)
        out.append(row)
    res = pd.DataFrame(out)
    res.to_csv(out_units, index=False)
    # Combined supported-units file keeps the per-regime flags so supported-vs-unsupported can be
    # cross-tabulated in one place; the three split files are convenient for training.
    for name in REGIMES:
        res[f"supported_{name}"] = res[f"verdict_{name}"].isin(["EP", "HP"])
    supported = res[res[[f"supported_{n}" for n in REGIMES]].any(axis=1)].copy()
    supported.to_csv(out_supported, index=False)
    for name in REGIMES:
        res[res[f"verdict_{name}"].isin(["EP", "HP"])].to_csv(
            run / f"supported_ep_hp_{name}.csv", index=False)

    total = len(res)
    print(f"\n(cve, file) units: {total}")
    print(f"{'regime':12s} {'EP':>7} {'HP':>7} {'EP+HP':>7} {'mismatch':>9} {'no_find':>8}")
    for name in REGIMES:
        v = res[f"verdict_{name}"].value_counts()
        ep, hp = int(v.get("EP", 0)), int(v.get("HP", 0))
        print(f"{name:12s} {ep:7d} {hp:7d} {ep+hp:7d} "
              f"{int(v.get('mismatch',0)):9d} {int(v.get('no_finding',0)):8d}")
    print("\nEP/HP-supported units (EP u HP) by regime:")
    for name in REGIMES:
        print(f"  {name:12s}: {int(res[f'supported_{name}'].sum())}")
    logging.info(f"Saved -> {out_units}, {out_supported}, {out_loc}")


if __name__ == "__main__":
    main()
