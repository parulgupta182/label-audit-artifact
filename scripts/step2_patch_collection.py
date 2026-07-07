"""
Corrected CVE-linked patch collection (v2) — replaces Step 3 Approach A.

Core fix: drive collection from each CVE's own GitHub reference URL, keep
cve_id + CWE on every record, fetch the EXACT linked commit/PR, extract
hunk-level snippets, and make linkage confidence explicit.

v2 changes (from review):
  - Language set restricted to the paper's scope (C/C++/Java/Python). Expand
    ONLY by editing CODE_EXTS deliberately.
  - confidence + link_source on every record (commit/pull = high/medium,
    search fallback = low) so the main dataset and the fallback never mix silently.
  - PR metadata (pr_number, pr_commit_count, commit_index_in_pr,
    is_multi_commit_pr) so large multi-commit PRs are separable.
  - Per-kind extraction/skip tally printed for the artifact README.
  - Pre-Semgrep assertions + diagnostic summary; CVEs WITHOUT a CWE are counted
    and reported (not asserted away), keeping the enrichment gap visible.

Requires: pandas, PyGithub      Env: GITHUB_TOKENS="tok1,tok2,..."
"""

import os
import re
import json
import time
import logging
import threading
import concurrent.futures
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from github import Github, Auth
from github.GithubException import GithubException, UnknownObjectException, RateLimitExceededException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("patch_collection_fixed.log"), logging.StreamHandler()],
)

# Paper scope: C, C++, Java, Python. Expand ONLY on purpose (and update the paper).
CODE_EXTS = (".py", ".java", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp")

# Reference kinds to collect. 'repo' uses the GitHub Search API (search_commits),
# which is capped at ~30 req/min and triggers long secondary "abuse" backoffs.
# Keep it OFF for the main high-confidence dataset (commit + pull = Tier 1+2).
# Enable the fallback only for a SEPARATE, single-worker supplementary run.
INCLUDE_KINDS = ("commit", "pull")
ENABLE_SEARCH_FALLBACK = False

# Fixed column order so incremental appends (and resumes) always align.
RECORD_COLUMNS = [
    "pr_number", "pr_commit_count", "commit_index_in_pr", "is_multi_commit_pr",
    "cve_id", "cwe_ids", "has_cwe", "is_multi_cve", "multi_cve_group_size",
    "repo", "reference_url", "link_source", "confidence",
    "commit_sha", "parent_sha", "is_merge_commit",
    "filename", "file_status", "additions", "deletions",
    "patch", "hunks", "commit_message", "commit_date",
]


# --------------------------------------------------------------------------- #
# 1. Build the work list FROM the CVE references
# --------------------------------------------------------------------------- #
def classify_github_url(url):
    p = urlparse(url)
    if "github.com" not in p.netloc.lower() or p.scheme not in ("http", "https"):
        return None
    parts = [x for x in p.path.strip("/").split("/") if x]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    if len(parts) >= 4 and parts[2] in ("commit", "commits"):
        return ("commit", parts[3].split("?")[0], owner, repo)
    if len(parts) >= 4 and parts[2] == "pull":
        m = re.match(r"\d+", parts[3])
        if m:
            return ("pull", int(m.group()), owner, repo)
    if len(parts) >= 4 and parts[2] == "compare":
        return ("compare", parts[3], owner, repo)
    if len(parts) >= 5 and parts[2] in ("blob", "tree"):
        return ("blob", (parts[3], "/".join(parts[4:])), owner, repo)
    return ("repo", None, owner, repo)


def _parse_refs(cell):
    if not isinstance(cell, str) or cell.strip() in ("", "nan", "None"):
        return []
    try:
        data = json.loads(cell.replace("'", '"').replace("None", "null")
                          .replace("True", "true").replace("False", "false"))
    except Exception:
        return []
    return [it["url"].strip() for it in data
            if isinstance(it, dict) and it.get("url")] if isinstance(data, list) else []


def build_worklist(cve_csv, cwe_class_csv):
    df_cve = pd.read_csv(cve_csv)
    cwe_map = {}
    if Path(cwe_class_csv).exists():
        dfc = pd.read_csv(cwe_class_csv)
        cwe_map = dfc.groupby("cve_id")["cwe_id"].apply(lambda s: sorted(set(s))).to_dict()

    rows = []
    for _, r in df_cve.iterrows():
        cve_id = r.get("cve_id")
        for url in _parse_refs(r.get("reference_json")):
            c = classify_github_url(url)
            if not c:
                continue
            kind, ref, owner, repo = c
            rows.append({"cve_id": cve_id, "cwe_ids": ";".join(cwe_map.get(cve_id, [])),
                         "owner": owner, "repo": repo, "kind": kind, "ref": ref, "url": url})
    wl = pd.DataFrame(rows).drop_duplicates(subset=["cve_id", "url"]).reset_index(drop=True)

    key = wl["owner"] + "/" + wl["repo"] + "#" + wl["kind"] + ":" + wl["ref"].astype(str)
    counts = key.value_counts()
    wl["multi_cve_group_size"] = key.map(counts)
    wl["is_multi_cve"] = wl["multi_cve_group_size"] > 1

    logging.info(f"Worklist: {len(wl)} (CVE, ref) items; "
                 f"{int(wl['is_multi_cve'].sum())} multi-CVE; "
                 f"kinds={wl['kind'].value_counts().to_dict()}")
    n_no_cwe = (wl['cwe_ids'] == '').sum()
    logging.info(f"Reference items whose CVE has NO CWE label: {n_no_cwe} "
                 f"({n_no_cwe/len(wl):.1%}) -- enrichment gap, kept but reported.")
    return wl


# --------------------------------------------------------------------------- #
# 2. Diff -> hunk-level snippets
# --------------------------------------------------------------------------- #
def parse_hunks(patch_text):
    if not patch_text:
        return []
    hunks, cur = [], None
    for line in patch_text.split("\n"):
        if line.startswith("@@"):
            if cur:
                hunks.append(cur)
            cur = {"header": line, "before": [], "after": []}
        elif cur is None:
            continue
        elif line.startswith("-") and not line.startswith("---"):
            cur["before"].append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            cur["after"].append(line[1:])
        elif line.startswith(" "):
            cur["before"].append(line[1:]); cur["after"].append(line[1:])
    if cur:
        hunks.append(cur)
    return [{"header": h["header"], "vulnerable_code": "\n".join(h["before"]),
             "patched_code": "\n".join(h["after"])} for h in hunks]


def _is_code(fn):
    return fn.lower().endswith(CODE_EXTS)


def _records_from_commit(commit, item, source, confidence, extra=None):
    out = []
    parents = commit.parents
    if not parents:                       # root commit -> no before/after possible; skip
        return out
    base = {  # consistent columns across all record types
        "pr_number": None, "pr_commit_count": None,
        "commit_index_in_pr": None, "is_multi_commit_pr": None,
    }
    if extra:
        base.update(extra)
    for f in commit.files:
        if not _is_code(f.filename) or not f.patch:
            continue
        rec = dict(base)
        rec.update({
            "cve_id": item["cve_id"], "cwe_ids": item["cwe_ids"],
            "has_cwe": bool(item["cwe_ids"]),
            "is_multi_cve": bool(item["is_multi_cve"]),
            "multi_cve_group_size": int(item["multi_cve_group_size"]),
            "repo": f"{item['owner']}/{item['repo']}", "reference_url": item["url"],
            "link_source": source, "confidence": confidence,
            "commit_sha": commit.sha,
            "parent_sha": parents[0].sha,
            "is_merge_commit": len(parents) > 1,
            "filename": f.filename, "file_status": f.status,
            "additions": f.additions, "deletions": f.deletions,
            "patch": f.patch, "hunks": json.dumps(parse_hunks(f.patch)),
            "commit_message": commit.commit.message,
            "commit_date": commit.commit.author.date.isoformat() if commit.commit.author else None,
        })
        out.append(rec)
    return out


# --------------------------------------------------------------------------- #
# 3. Resolve each CVE reference to its real fix commit(s)
# --------------------------------------------------------------------------- #
def collect_for_target(g, owner, repo_name, kind, ref, members):
    """Fetch a commit/PR ONCE and fan results out to every CVE that references it.
       `members` = worklist rows sharing (owner, repo, kind, ref).
       Returns (records, outcome)."""
    full = f"{owner}/{repo_name}"
    try:
        repo = g.get_repo(full)
    except (UnknownObjectException, GithubException) as e:
        logging.warning(f"Repo unavailable {full}: {e}")
        return [], "skipped"

    def fan(commit, source, confidence, extra=None):
        out = []
        for it in members:                       # one fetched commit -> records per CVE
            out.extend(_records_from_commit(commit, it, source, confidence, extra))
        return out

    try:
        if kind == "commit":
            recs = fan(repo.get_commit(ref), "commit", "high")
            return recs, ("extracted" if recs else "skipped")

        if kind == "pull":
            pr = repo.get_pull(int(ref))
            commits = [c for c in pr.get_commits() if len(c.parents) <= 1]  # skip inner merges
            n = len(commits)
            recs = []
            for i, c in enumerate(commits):
                conf = "high" if n == 1 else "medium"  # multi-commit PRs may add unrelated code
                recs.extend(fan(repo.get_commit(c.sha), "pull", conf,
                                extra={"pr_number": int(ref), "pr_commit_count": n,
                                       "commit_index_in_pr": i, "is_multi_commit_pr": n > 1}))
            return recs, ("extracted" if recs else "skipped")

        if kind == "repo" and ENABLE_SEARCH_FALLBACK:
            # Supplementary only (low confidence). GitHub Search API -> heavy limits.
            recs = []
            for cid in sorted({m["cve_id"] for m in members}):
                cid_members = [m for m in members if m["cve_id"] == cid]
                try:
                    for c in list(g.search_commits(query=f"{cid} repo:{full}"))[:3]:
                        if len(c.parents) > 1:
                            continue
                        commit = repo.get_commit(c.sha)
                        for it in cid_members:
                            recs.extend(_records_from_commit(commit, it, "search", "low"))
                except GithubException:
                    pass
            return recs, ("extracted" if recs else "skipped")

        # compare / blob / disabled repo-search: classified but not extracted.
        return [], "skipped"

    except RateLimitExceededException:
        raise
    except GithubException as e:
        logging.error(f"Resolve error {kind}:{ref} in {full}: {e}")
        return [], "skipped"


# --------------------------------------------------------------------------- #
# 4. Run + per-kind tally + sanity checks
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


def write_readme(df, tally, n_refs, out_csv, path="README_dataset.md"):
    """Auto-generate the auditable extraction summary so the README always
    matches the data. `tally` = {kind: (total, extracted)} computed from disk."""
    exts = (df["filename"].str.lower().str.extract(r"(\.[a-z0-9]+)$")[0]
            .value_counts().to_dict())
    L = []
    L.append("# CVE-linked patch corpus — extraction summary\n")
    L.append(f"Source file: `{out_csv}`\n")

    L.append("## Reference extraction\n")
    L.append(f"- Total GitHub references processed: {n_refs}\n")
    L.append("\n| kind | total | extracted | skipped |\n|---|---|---|---|")
    for k in sorted(tally):
        tot, ext = tally[k]
        L.append(f"| {k} | {tot} | {ext} | {tot - ext} |")

    L.append("\n## Patch records\n")
    L.append(f"- Total patch records: {len(df)}")
    L.append(f"- Unique CVEs: {df['cve_id'].nunique()} | unique commits: {df['commit_sha'].nunique()}")
    L.append("\nBy link_source:\n")
    for k, v in df["link_source"].value_counts().items():
        L.append(f"- {k}: {v}")
    L.append("\nBy confidence:\n")
    for k, v in df["confidence"].value_counts().items():
        L.append(f"- {k}: {v}")

    L.append("\n## CWE label coverage (NVD enrichment gap, reported not hidden)\n")
    L.append(f"- Records with any CWE: {int(df['has_cwe'].sum())}")
    L.append(f"- Records with a real CWE (CWE-<n>): {int(df['has_real_cwe'].sum())}")
    L.append(f"- Records without a real CWE: {int((~df['has_real_cwe']).sum())}")
    L.append(f"- CVEs with a real CWE: {df.loc[df['has_real_cwe'], 'cve_id'].nunique()}")
    L.append(f"- CVEs without a real CWE: {df.loc[~df['has_real_cwe'], 'cve_id'].nunique()}")

    L.append("\n## Provenance characteristics\n")
    L.append(f"- Single-CVE records: {int((~df['is_multi_cve']).sum())} | multi-CVE records: {int(df['is_multi_cve'].sum())}")
    pr = df[df["link_source"] == "pull"]
    if not pr.empty:
        L.append(f"- Single-commit PR records: {int((~pr['is_multi_commit_pr'].astype(bool)).sum())} "
                 f"| multi-commit PR records: {int(pr['is_multi_commit_pr'].astype(bool).sum())}")
    L.append(f"- Merge-commit records: {int(df['is_merge_commit'].sum())}")

    L.append("\n## File-extension distribution\n")
    for e, c in exts.items():
        L.append(f"- {e}: {c}")

    L.append("\n## Corpus taxonomy\n")
    L.append("| corpus | definition | size |\n|---|---|---|")
    L.append(f"| Extracted patch corpus | all CVE-linked patches, valid provenance | {len(df)} |")
    L.append(f"| CWE-labeled corpus | extracted + CVE has a real CWE (input to consistency) | {int(df['has_real_cwe'].sum())} |")
    L.append("| Evidence-bearing corpus | CWE-labeled + CWE-mapped Semgrep finding | computed downstream |")
    L.append("| EP/HP-supported units | EP∪HP samples (conservative high-confidence subset) | computed downstream |")

    Path(path).write_text("\n".join(L), encoding="utf-8")
    logging.info(f"Wrote artifact README -> {path}")


def _finalize(worklist, out_csv, done_path):
    """Compute flags, assertions, diagnostics, tally and README from what's on
    disk -- so the report is correct even after stop/resume cycles."""
    df = pd.read_csv(out_csv, engine="python")
    if df.empty:
        logging.warning("No records on disk."); return df

    cwe_str = df["cwe_ids"].fillna("").astype(str).str.strip()
    df["has_cwe"] = cwe_str.ne("")
    df["has_real_cwe"] = cwe_str.str.contains(r"CWE-\d+", regex=True)  # excludes NVD-CWE-*
    df.to_csv(out_csv, index=False)   # rewrite once with the flag columns

    required_cols = ["cve_id", "repo", "reference_url", "link_source",
                     "commit_sha", "parent_sha", "filename", "patch", "hunks"]
    for col in required_cols:
        assert col in df.columns, f"Missing required column: {col}"
        assert df[col].notna().all(), f"Null values in required column: {col}"

    # tally from worklist (totals) + disk (extracted refs) -> resume-proof
    total_by_kind = worklist["kind"].value_counts().to_dict()
    src2kind = {"commit": "commit", "pull": "pull", "search": "repo"}
    ext_kind = (df.assign(_k=df["link_source"].map(src2kind).fillna(df["link_source"]))
                  .drop_duplicates(["cve_id", "reference_url"])
                  .groupby("_k").size().to_dict())
    tally = {k: (total_by_kind.get(k, 0), ext_kind.get(k, 0))
             for k in set(total_by_kind) | set(ext_kind)}

    print("\n=== Reference kind: total | extracted | skipped ===")
    for k in sorted(tally):
        tot, ext = tally[k]
        print(f"  {k:8s}: {tot:7d} | {ext:7d} | {tot-ext:7d}")

    print("\n=== CWE coverage (enrichment gap reported, not discarded) ===")
    print(f"records: {len(df)} | with any CWE: {int(df['has_cwe'].sum())} | "
          f"with real CWE: {int(df['has_real_cwe'].sum())} | "
          f"without real CWE: {int((~df['has_real_cwe']).sum())}")
    print(f"CVEs with real CWE: {df.loc[df['has_real_cwe'], 'cve_id'].nunique()} | "
          f"without: {df.loc[~df['has_real_cwe'], 'cve_id'].nunique()}")

    print("\n=== Diagnostics ===")
    print("confidence:\n" + df["confidence"].value_counts().to_string())
    print("link_source:\n" + df["link_source"].value_counts().to_string())
    print(f"multi-CVE records: {int(df['is_multi_cve'].sum())} | "
          f"merge-commit records: {int(df['is_merge_commit'].sum())}")
    print("CVEs per commit:\n" +
          df.groupby('commit_sha')['cve_id'].nunique().describe().to_string())

    write_readme(df, tally, len(worklist), out_csv)
    print("\nExtracted patch corpus -> df                                     (provenance/coverage)")
    print("CWE-labeled corpus     -> df[df.has_real_cwe]                      (input to consistency)")
    print("Main paper dataset     -> df[df.confidence.isin(['high','medium'])]  (commit + pull)")
    logging.info(f"Finalized {len(df)} linked records -> {out_csv}")
    return df


def run(worklist, tokens, max_workers=3, out_csv="security_patches_linked.csv",
        pause=0.2, checkpoint_every=200, done_path="checkpoint_done_targets.txt"):
    tm = TokenManager(tokens)

    # ---- group identical targets so each commit/PR is fetched ONCE ----
    def tkey(o, r, k, ref):
        return f"{o}/{r}|{k}|{ref}"
    targets = []
    for (owner, repo_name, kind, ref), grp in worklist.groupby(
            ["owner", "repo", "kind", "ref"], dropna=False, sort=False):
        targets.append((owner, repo_name, kind, ref, grp.to_dict("records")))

    # ---- resume: skip targets already recorded in the checkpoint ----
    done = set()
    if os.path.exists(done_path):
        with open(done_path, encoding="utf-8") as fh:
            done = {ln.strip() for ln in fh if ln.strip()}
    pending = [t for t in targets if tkey(t[0], t[1], t[2], t[3]) not in done]
    logging.info(f"{len(worklist)} references -> {len(targets)} unique targets "
                 f"({len(worklist)-len(targets)} duplicate fetches avoided); "
                 f"{len(done)} done, {len(pending)} pending")
    if not pending:
        logging.info("Nothing pending -- finalizing from existing checkpoint.")
        return _finalize(worklist, out_csv, done_path)

    lock = threading.Lock()
    buf_rec, buf_done = [], []
    csv_exists = os.path.exists(out_csv)

    def flush():
        nonlocal csv_exists
        if buf_rec:
            (pd.DataFrame(buf_rec).reindex(columns=RECORD_COLUMNS)
             .to_csv(out_csv, mode="a", header=not csv_exists, index=False))
            csv_exists = True
            buf_rec.clear()
        if buf_done:
            with open(done_path, "a", encoding="utf-8") as fh:
                fh.write("\n".join(buf_done) + "\n")
            buf_done.clear()

    def work(target):
        owner, repo_name, kind, ref, members = target
        key = tkey(owner, repo_name, kind, ref)
        for _ in range(3):
            tok = tm.get()
            g = Github(auth=Auth.Token(tok), per_page=100)
            try:
                if pause:
                    time.sleep(pause)            # gentle pacing -> avoid secondary limits
                recs, _ = collect_for_target(g, owner, repo_name, kind, ref, members)
                with lock:
                    buf_rec.extend(recs)
                    buf_done.append(key)         # definitive: success OR 404-skip
                return
            except RateLimitExceededException:
                tm.penalize(tok); time.sleep(5)
        # exhausted retries (rate limit): do NOT mark done -> retried on resume
        logging.warning(f"Gave up (will retry on resume): {key}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(work, t): t for t in pending}
        n = 0
        for _ in concurrent.futures.as_completed(futs):
            n += 1
            if n % checkpoint_every == 0:
                with lock:
                    flush()
                logging.info(f"{n}/{len(pending)} targets done (checkpointed)")
    with lock:
        flush()
    logging.info("Collection pass complete; finalizing.")
    return _finalize(worklist, out_csv, done_path)


if __name__ == "__main__":
    toks = [t.strip() for t in os.getenv("GITHUB_TOKENS", "").split(",") if t.strip()]
    if not toks:
        raise RuntimeError("Set GITHUB_TOKENS as a comma-separated list.")
    wl = build_worklist("cve_data.csv", "cwe_classification.csv")
    wl = wl[wl["kind"].isin(INCLUDE_KINDS)].copy()        # Tier 1+2: commit + pull only
    print("High-confidence worklist (Tier 1+2):")
    print(wl["kind"].value_counts().to_string())
    print("Total references:", len(wl))
    run(wl, toks, max_workers=3, pause=1.5)
                         # 3 tokens (separate accounts); drop to 1-2 if limited
