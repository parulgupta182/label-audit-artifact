"""
Semgrep stage 1 — materialize vulnerable (before) files + manifest + hunk ranges.

Replaces create_git_repositories.ipynb (no cloud, no GitHub pushes). Reads the
corrected corpus, fetches each unique (repo, parent_sha, filename) at the PARENT
commit (vulnerable version), writes scan_corpus/<lang>/, and records:
  * scan_manifest.csv  -> join Semgrep findings back to provenance
  * hunk_ranges.csv    -> vulnerable before-side line ranges for localization
                          tagging (in_hunk / in_context / elsewhere) in stage 4

Reference label = per-CVE NVD cwe_ids. Checkpointed/resumable; token-rotated.
Run only AFTER security_patches_linked.csv is finalized (needs has_real_cwe).
Env: GITHUB_TOKENS="tok1,tok2,...".
"""

import os
import re
import csv
import json
import time
import hashlib
import logging
import threading
import concurrent.futures
from pathlib import Path
from urllib.parse import quote

import pandas as pd
import requests

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[logging.FileHandler("materialize.log"), logging.StreamHandler()])

INPUT_CSV = r"security_patches_linked.csv"
CORPUS_DIR = Path("scan_corpus")
MANIFEST = "scan_manifest.csv"
HUNK_RANGES = "hunk_ranges.csv"
DONE_PATH = "materialize_done.txt"

ONLY_REAL_CWE = True
CONFIDENCE_KEEP = ("high", "medium")
CONTEXT = 10                      # +/- lines around a hunk for the "in_context" band

EXT_LANG = {".py": "python", ".java": "java", ".c": "c", ".h": "c",
            ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp"}

REQUEST_TIMEOUT = 30
MAX_RETRIES = 4
CHECKPOINT_EVERY = 200
RETRYABLE = {403, 429, 500, 502, 503, 504}

_HDR = re.compile(r"@@ -(\d+)(?:,(\d+))? \+")


def lang_of(filename):
    return EXT_LANG.get(Path(str(filename)).suffix.lower())


def file_key(repo, parent_sha, filename):
    return hashlib.sha1(f"{repo}|{parent_sha}|{filename}".encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# hunk ranges (local; no network)
# --------------------------------------------------------------------------- #
def parse_before_range(header):
    """'@@ -a,b +c,d @@' -> (before_start, before_len). Implicit len = 1."""
    m = _HDR.match(str(header))
    if not m:
        return None
    start = int(m.group(1))
    length = int(m.group(2)) if m.group(2) is not None else 1
    return start, length


def build_hunk_ranges(df):
    rows = []
    for r in df.itertuples(index=False):
        try:
            hunks = json.loads(r.hunks) if isinstance(r.hunks, str) else []
        except Exception:
            hunks = []
        fk = file_key(r.repo, r.parent_sha, r.filename)
        for i, h in enumerate(hunks):
            pr = parse_before_range(h.get("header", ""))
            if not pr:
                continue
            bstart, blen = pr
            added_only = blen == 0          # e.g. '@@ -0,0 +1,5 @@' : no before-side
            bend = bstart - 1 if added_only else bstart + blen - 1
            rows.append({
                "file_key": fk, "cve_id": r.cve_id, "cwe_ids": r.cwe_ids,
                "repo": r.repo, "parent_sha": r.parent_sha, "filename": r.filename,
                "hunk_index": i, "before_start": bstart, "before_len": blen,
                "before_end": bend, "added_only": int(added_only),
                "ctx_start": max(1, bstart - CONTEXT),
                "ctx_end": (None if added_only else bend + CONTEXT),
                "confidence": getattr(r, "confidence", None),
                "link_source": getattr(r, "link_source", None),
                "commit_sha": getattr(r, "commit_sha", None),
                "reference_url": getattr(r, "reference_url", None),
            })
    cols = ["file_key", "cve_id", "cwe_ids", "repo", "parent_sha", "filename",
            "hunk_index", "before_start", "before_len", "before_end", "added_only",
            "ctx_start", "ctx_end", "confidence", "link_source", "commit_sha", "reference_url"]
    hr = pd.DataFrame(rows, columns=cols)
    if not hr.empty:
        hr = hr.drop_duplicates(subset=["file_key", "cve_id", "hunk_index"])
    hr.to_csv(HUNK_RANGES, index=False)
    n_added = int(hr["added_only"].sum()) if not hr.empty else 0
    logging.info(f"Hunk ranges: {len(hr)} rows ({n_added} added-only) -> {HUNK_RANGES}")


# --------------------------------------------------------------------------- #
# fetch
# --------------------------------------------------------------------------- #
class TokenManager:
    def __init__(self, tokens):
        self.usage = {t: 0 for t in tokens}; self.lock = threading.Lock()

    def get(self):
        with self.lock:
            t = min(self.usage.items(), key=lambda x: x[1])[0]
            self.usage[t] += 1
            return t

    def penalize(self, t):
        with self.lock:
            self.usage[t] += 100000


_local = threading.local()


def session():
    if not hasattr(_local, "s"):
        _local.s = requests.Session()      # one Session per worker thread
    return _local.s


def fetch_raw(repo, parent_sha, filename, tm):
    url = f"https://api.github.com/repos/{repo}/contents/{quote(filename, safe='/')}"
    for attempt in range(MAX_RETRIES):
        tok = tm.get()
        headers = {"Authorization": f"token {tok}",
                   "Accept": "application/vnd.github.v3.raw"}
        try:
            r = session().get(url, headers=headers, params={"ref": parent_sha},
                              timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            time.sleep(2 * (attempt + 1)); continue
        if r.status_code == 200:
            return r.text, None
        if r.status_code == 404:
            return None, "http_404"          # file didn't exist at parent (added file)
        if r.status_code in RETRYABLE:
            tm.penalize(tok)
            reset = r.headers.get("X-RateLimit-Reset")
            wait = max(int(reset) - int(time.time()), 5) if reset else 5 * (attempt + 1)
            logging.warning(f"{r.status_code} on {repo}/{filename}; wait {min(wait,90)}s")
            time.sleep(min(wait, 90)); continue
        return None, f"http_{r.status_code}"
    return None, "exhausted"


def main():
    toks = [t.strip() for t in os.getenv("GITHUB_TOKENS", "").split(",") if t.strip()]
    if not toks:
        raise RuntimeError("Set GITHUB_TOKENS.")
    CORPUS_DIR.mkdir(exist_ok=True)
    csv.field_size_limit(2147483647 if os.name != "nt" else 2147483646)

    df = pd.read_csv(INPUT_CSV, engine="python")
    if ONLY_REAL_CWE:
        if "has_real_cwe" not in df.columns:
            raise RuntimeError("has_real_cwe missing -- run only after "
                               "security_patches_linked.csv is finalized.")
        df = df[df["has_real_cwe"] == True].copy()
    if "confidence" in df.columns:
        df = df[df["confidence"].isin(CONFIDENCE_KEEP)].copy()

    build_hunk_ranges(df)        # local, write early

    uniq = (df.dropna(subset=["repo", "parent_sha", "filename"])
              .drop_duplicates(subset=["repo", "parent_sha", "filename"])
              [["repo", "parent_sha", "filename"]].reset_index(drop=True))
    uniq = uniq[uniq["filename"].map(lang_of).notna()].copy()
    logging.info(f"{len(df)} records -> {len(uniq)} unique before-files to fetch")

    done = set()
    if os.path.exists(DONE_PATH):
        with open(DONE_PATH, encoding="utf-8") as fh:
            done = {ln.strip() for ln in fh if ln.strip()}
    manifest_exists = os.path.exists(MANIFEST)
    jobs = [r for r in uniq.to_dict("records")
            if file_key(r["repo"], r["parent_sha"], r["filename"]) not in done]
    logging.info(f"{len(done)} done, {len(jobs)} pending")
    if not jobs:
        logging.info("Nothing pending."); return

    tm = TokenManager(toks)
    lock = threading.Lock()
    man_buf, done_buf = [], []

    def flush():
        nonlocal manifest_exists
        if man_buf:
            pd.DataFrame(man_buf).to_csv(MANIFEST, mode="a",
                                         header=not manifest_exists, index=False)
            manifest_exists = True; man_buf.clear()
        if done_buf:
            with open(DONE_PATH, "a", encoding="utf-8") as fh:
                fh.write("\n".join(done_buf) + "\n")
            done_buf.clear()

    def work(rec):
        repo, parent_sha, filename = rec["repo"], rec["parent_sha"], rec["filename"]
        key = file_key(repo, parent_sha, filename)
        lang = lang_of(filename)
        content, err = fetch_raw(repo, parent_sha, filename, tm)
        local_path = None
        if content is not None:
            out = CORPUS_DIR / lang / f"{key}__{Path(filename).name}"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8", errors="replace")
            local_path = str(out)
        with lock:
            man_buf.append({"file_key": key, "local_path": local_path, "repo": repo,
                            "parent_sha": parent_sha, "filename": filename,
                            "language": lang, "fetch_ok": content is not None, "error": err})
            done_buf.append(key)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futs = {ex.submit(work, r): r for r in jobs}
        n = 0
        for _ in concurrent.futures.as_completed(futs):
            n += 1
            if n % CHECKPOINT_EVERY == 0:
                with lock:
                    flush()
                logging.info(f"{n}/{len(jobs)} files (checkpointed)")
    with lock:
        flush()

    man = pd.read_csv(MANIFEST)
    ok = int(man["fetch_ok"].sum())
    logging.info(f"Manifest: {len(man)} files | fetched {ok} | missing/other {len(man)-ok}")
    logging.info("Next: semgrep scan --config <RULESET> --json -o semgrep_raw.json scan_corpus/")


if __name__ == "__main__":
    main()
