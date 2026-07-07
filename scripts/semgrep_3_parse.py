"""
Semgrep stage 3 — parse local Semgrep JSON into a findings table.

Replaces get_semgrep_scan_results_from_api.ipynb AND map_rulename_to_cwe.ipynb:
the CWE comes straight from extra.metadata.cwe in the local --json output.
Keeps start_line and end_line so stage 4 can localize findings to hunk ranges.

    python semgrep_3_parse.py        # semgrep_raw.json -> semgrep_findings.csv
"""

import re
import json
import logging
import argparse
from pathlib import Path

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def norm_cwes(cwe_field):
    items = cwe_field if isinstance(cwe_field, list) else [cwe_field]
    out = []
    for c in items:
        m = re.search(r"CWE-(\d+)", str(c))
        if m:
            out.append(f"cwe-{m.group(1)}")
    return out


def file_key_from_path(p):
    base = Path(str(p)).name
    cand = base.split("__", 1)[0]
    return cand if re.fullmatch(r"[0-9a-f]{16}", cand) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", default=".", help="folder for semgrep_raw.json + outputs")
    args = ap.parse_args()
    run = Path(args.run_dir)
    raw, out = run / "semgrep_raw.json", run / "semgrep_findings.csv"

    data = json.loads(raw.read_text(encoding="utf-8"))
    rows = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        found = norm_cwes(extra.get("metadata", {}).get("cwe"))
        rows.append({
            "file_key": file_key_from_path(r.get("path")),
            "path": r.get("path"),
            "rule_id": r.get("check_id"),
            "message": (extra.get("message") or "")[:500],
            "severity": extra.get("severity"),
            "start_line": r.get("start", {}).get("line"),
            "end_line": r.get("end", {}).get("line"),
            "semgrep_cwe": found[0] if found else None,   # primary (matches paper)
            "all_found_cwes": ";".join(found),
        })
    df = pd.DataFrame(rows)
    df.to_csv(out, index=False)
    logging.info(f"{len(df)} findings | no path key: {int(df['file_key'].isna().sum())} | "
                 f"no CWE in metadata: {int(df['semgrep_cwe'].isna().sum())} -> {out}")


if __name__ == "__main__":
    main()
