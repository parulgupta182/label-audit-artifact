"""
NVD data collection via the official API 2.0 (replaces the retired 1.1 feeds).

Outputs (schema consumed by patch_collection_fixed.py):
  cve_data.csv          : one row per CVE  (cve_id, published, last_modified,
                          vuln_status, severity, description, reference_json)
  cwe_classification.csv: one row per (cve_id, cwe_id)  (+ source, type)

Notes:
  - Get a free API key (https://nvd.nist.gov/developers/request-an-api-key) and
    set NVD_API_KEY. Without a key the rate limit is 5 req / 30s (~6s/request);
    with a key it is 50 req / 30s (~0.6s/request). A full pull is ~180 requests.
  - Full historical pull: leave PUB_START / PUB_END as None (pages through all
    ~358k records). Incremental: set a <=120-day window (API caps date ranges).
  - The script prints CVEs-with-CWE vs CVEs-without-CWE per year so the
    post-2024 NVD enrichment cliff is visible before you pick a cutoff.
"""

import os
import csv
import json
import time
import logging
import datetime as dt

import requests

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[logging.FileHandler("nvd_collect.log"), logging.StreamHandler()])

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000                       # max allowed
OUT_CVE = "cve_data.csv"
OUT_CWE = "cwe_classification.csv"

# Optional published-date window (extended ISO-8601). None,None => full pull.
# Date ranges are capped at 120 days by the API; the loop below auto-chunks.
PUB_START = None                  # e.g. "2002-01-01T00:00:00.000"
PUB_END = None                    # e.g. "2025-12-31T23:59:59.999"

API_KEY = os.getenv("NVD_API_KEY", "").strip()
SLEEP = 0.7 if API_KEY else 6.5   # stay under the documented rate limits
RETRYABLE = {403, 429, 500, 502, 503, 504}


def nvd_get(params, retries=5):
    headers = {"apiKey": API_KEY} if API_KEY else {}
    for attempt in range(retries):
        try:
            r = requests.get(BASE_URL, params=params, headers=headers, timeout=60)
        except requests.RequestException as e:
            logging.warning(f"Request error: {e} (retry {attempt+1}/{retries})")
            time.sleep(SLEEP * (attempt + 1))
            continue
        if r.status_code == 200:
            return r.json()
        if r.status_code in RETRYABLE:
            wait = SLEEP * (attempt + 2)
            logging.warning(f"HTTP {r.status_code}; waiting {wait:.0f}s (retry {attempt+1}/{retries})")
            time.sleep(wait)
            continue
        r.raise_for_status()
    raise RuntimeError("Exhausted retries on NVD API")


def english_desc(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def severity(cve):
    m = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if m.get(key):
            return m[key][0].get("cvssData", {}).get("baseSeverity", "")
    if m.get("cvssMetricV2"):
        return m["cvssMetricV2"][0].get("baseSeverity", "")
    return ""


def cwes(cve):
    """Return list of (cwe_id, source, type) for real CWE / NVD placeholder values."""
    out = []
    for w in cve.get("weaknesses", []):
        src, typ = w.get("source", ""), w.get("type", "")
        for d in w.get("description", []):
            val = (d.get("value") or "").strip()
            if val.startswith("CWE-") or val.startswith("NVD-CWE-"):
                out.append((val, src, typ))
    # de-dup while preserving order
    seen, dedup = set(), []
    for t in out:
        if t[0] not in seen:
            seen.add(t[0]); dedup.append(t)
    return dedup


def iter_windows():
    """Yield param dicts. Full pull = one open query; else 120-day chunks."""
    if not (PUB_START and PUB_END):
        yield {}
        return
    fmt = "%Y-%m-%dT%H:%M:%S.%f"
    start = dt.datetime.strptime(PUB_START, fmt)
    end = dt.datetime.strptime(PUB_END, fmt)
    while start < end:
        chunk_end = min(start + dt.timedelta(days=119), end)
        yield {"pubStartDate": start.strftime(fmt)[:-3],
               "pubEndDate": chunk_end.strftime(fmt)[:-3]}
        start = chunk_end + dt.timedelta(milliseconds=1)


def collect():
    cve_rows, cwe_rows = [], []
    seen_cve = set()

    for win in iter_windows():
        start_index, total = 0, None
        while True:
            params = {"resultsPerPage": PAGE, "startIndex": start_index, "noRejected": "", **win}
            data = nvd_get(params)
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                cve = item.get("cve", {})
                cid = cve.get("id")
                if not cid or cid in seen_cve:
                    continue
                seen_cve.add(cid)

                refs = [{"url": r.get("url"), "tags": r.get("tags", [])}
                        for r in cve.get("references", []) if r.get("url")]
                cve_rows.append({
                    "cve_id": cid,
                    "published": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", ""),
                    "vuln_status": cve.get("vulnStatus", ""),
                    "severity": severity(cve),
                    "description": english_desc(cve),
                    "reference_json": json.dumps(refs),     # clean double-quoted JSON
                })
                for cwe_id, src, typ in cwes(cve):
                    cwe_rows.append({"cve_id": cid, "cwe_id": cwe_id,
                                     "source": src, "type": typ})

            start_index += len(vulns)
            logging.info(f"{start_index}/{total} (window={win or 'ALL'}); "
                         f"{len(cve_rows)} CVEs, {len(cwe_rows)} CWE links")
            if start_index >= total:
                break
            time.sleep(SLEEP)

    return cve_rows, cwe_rows


def write_csv(rows, path, fields):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    logging.info(f"Wrote {len(rows)} rows -> {path}")


def report_enrichment_gap(cve_rows, cwe_rows):
    """Show CVEs with vs without a CWE per year — makes the post-2024 cliff visible."""
    has_cwe = set(r["cve_id"] for r in cwe_rows
                  if not r["cwe_id"].startswith("NVD-CWE"))  # real CWE only
    by_year = {}
    for r in cve_rows:
        yr = (r["published"] or "----")[:4]
        d = by_year.setdefault(yr, [0, 0])
        d[0] += 1
        if r["cve_id"] in has_cwe:
            d[1] += 1
    logging.info("Year | total | with_real_CWE | coverage")
    for yr in sorted(by_year):
        tot, wc = by_year[yr]
        logging.info(f"{yr} | {tot:6d} | {wc:6d} | {wc/tot:.0%}" if tot else yr)


if __name__ == "__main__":
    cve_rows, cwe_rows = collect()
    write_csv(cve_rows, OUT_CVE,
              ["cve_id", "published", "last_modified", "vuln_status",
               "severity", "description", "reference_json"])
    write_csv(cwe_rows, OUT_CWE, ["cve_id", "cwe_id", "source", "type"])
    report_enrichment_gap(cve_rows, cwe_rows)
    logging.info("Next: python patch_collection_fixed.py  (consumes these two CSVs)")
