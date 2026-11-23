from pathlib import Path
from collections import defaultdict, deque
import re

import pandas as pd
from rdflib import Dataset, URIRef

ROOT = Path(__file__).resolve().parents[1] / "data"

def read_csv(name):
    return pd.read_csv(
        ROOT / name,
        dtype={"file_key": str, "cve_id": str},
        low_memory=False
    )

units = read_csv("consistency_units_merged.csv")
findings = read_csv("semgrep_findings.csv")
hunks = read_csv("hunk_ranges.csv")

# Load CWE hierarchy.
ds = Dataset()
ds.parse(ROOT / "named_graphs_cwe.trig", format="trig")
predicate = URIRef("http://schema.org/child_of")

parents = defaultdict(set)
children = defaultdict(set)

for child, _, parent, _ in ds.quads(
    (None, predicate, None, None)
):
    c = str(child).rsplit("/", 1)[-1]
    p = str(parent).rsplit("/", 1)[-1]
    parents[c].add(p)
    children[p].add(c)

def cwe_number(value):
    if not isinstance(value, str):
        return None
    match = re.search(r"(\d+)", value)
    return match.group(1) if match else None

def reachable(start, graph):
    visited = set()
    queue = deque([start])
    while queue:
        for neighbor in graph.get(queue.popleft(), ()):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return visited

related_cache = {}

def classify(found, reference):
    if found in reference:
        return "EP"
    if found not in related_cache:
        related_cache[found] = (
            reachable(found, parents)
            | reachable(found, children)
        )
    return (
        "HP" if related_cache[found] & reference
        else "mismatch"
    )

# Index scanner findings by file.
by_file = defaultdict(list)

for f in findings.itertuples(index=False):
    cwe = cwe_number(f.semgrep_cwe)
    if cwe and pd.notna(f.start_line):
        start = int(f.start_line)
        end = (
            int(f.end_line)
            if pd.notna(f.end_line) else start
        )
        by_file[f.file_key].append((start, end, cwe))

# Index before-side hunk and context intervals.
intervals = defaultdict(list)

for h in hunks.itertuples(index=False):
    if str(h.added_only).strip().lower() in (
        "1", "true", "yes"
    ):
        continue

    intervals[(h.cve_id, h.file_key)].append((
        int(h.before_start),
        int(h.before_end),
        int(h.ctx_start),
        int(h.ctx_end)
    ))

def verdict(matches):
    if not matches:
        return "no_finding"
    if "EP" in matches:
        return "EP"
    if "HP" in matches:
        return "HP"
    return "mismatch"

differences = []
counts = defaultdict(int)

for u in units.itertuples(index=False):
    reference = {
        cwe_number(c)
        for c in str(u.groundtruth_cwes).split(";")
        if cwe_number(c)
    }

    key = (u.cve_id, u.file_key)
    ivs = intervals.get(key, [])

    whole = []
    context = []
    strict = []

    for start, end, found in by_file.get(u.file_key, []):
        match = classify(found, reference)
        whole.append(match)

        in_hunk = any(
            start <= b and end >= a
            for a, b, _, _ in ivs
        )

        in_context = any(
            start <= d and end >= c
            for _, _, c, d in ivs
        )

        if in_hunk:
            strict.append(match)
            context.append(match)
        elif in_context:
            context.append(match)

    computed = {
        "whole_file": verdict(whole),
        "hunk_ctx": verdict(context),
        "hunk_strict": verdict(strict)
    }

    for regime, actual in computed.items():
        expected = getattr(u, f"verdict_{regime}")
        counts[(regime, actual)] += 1

        if actual != expected:
            differences.append({
                "cve_id": u.cve_id,
                "file_key": u.file_key,
                "regime": regime,
                "expected": expected,
                "reconstructed": actual
            })

print("Units checked:", len(units))
print("Verdict comparisons:", len(units) * 3)
print("Mismatched comparisons:", len(differences))

for regime in ("whole_file", "hunk_ctx", "hunk_strict"):
    print(f"\n{regime}:")
    for label in ("EP", "HP", "mismatch", "no_finding"):
        print(f"  {label}: {counts[(regime, label)]}")

if differences:
    output = ROOT.parent / "verdict_discrepancies.csv"
    pd.DataFrame(differences).to_csv(output, index=False)
    print(f"\nDiscrepancies saved to: {output}")
    print("OVERALL: FAIL — investigate differences")
    raise SystemExit(1)
else:
    print("\nOVERALL: PASS — all verdicts reproduced")