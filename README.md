# Provenance-Preserving Auditing of Vulnerability Labels in Large-Scale CVE-Derived Datasets

**Research Artifact — ANUBIS 2026 (ESORICS 2026 Workshops)**

**Authors:** Parul Gupta, Lea Achter, Julienne Eder, and Hans-Joachim Hof

**Affiliation:** Technische Hochschule Ingolstadt (THI), Germany

**Venue:** 2nd International Workshop on Assessment with New Methodologies, Unified Benchmarks, and Environments, of Intrusion Detection and Response Systems (ANUBIS 2026), co-located with the 31st European Symposium on Research in Computer Security (ESORICS 2026).

**Paper:** [Read the paper (PDF)](https://superviz.inria.fr/assets/pdf/anubis26/ESORICS_2026_paper_1192.pdf)

**Workshop:** [ANUBIS 2026](https://superviz.inria.fr/anubis26/)

---

## Overview

This repository contains the research artifact accompanying the paper *"Provenance-Preserving Auditing of Vulnerability Labels in Large-Scale CVE-Derived Datasets"* presented at ANUBIS 2026.

The study investigates the consistency between CVE-assigned Common Weakness Enumeration (CWE) labels and static-analysis evidence in vulnerability-related source-code files.

The artifact supports provenance-preserving vulnerability dataset construction and auditing, including:

- Collection of CVE records and associated source-code references.
- Extraction of vulnerability-fixing patches from linked repositories.
- Construction of CWE hierarchy information for label-consistency analysis.
- Processing and evaluation of Semgrep findings.
- Comparison of CWE labels against static-analysis evidence using hierarchy-aware matching.
- Evidence localization under whole-file, hunk-context, and hunk-strict evaluation regimes.
- Analysis of label agreement, evidence coverage, and provenance confidence.

The repository provides analysis scripts, sample data, and aggregate experimental results.

**Reproducibility scope:** The full materialized source-code corpus is not distributed. Reproducing the complete analysis requires reconstructing the dataset from its original sources and executing the static-analysis pipeline. Some stages require external services, API credentials, and Semgrep Pro access.

---

## Reproducing the Evaluation Results

This repository provides derived metadata sufficient to independently reconstruct the CWE-consistency verdicts reported in the ANUBIS 2026 study.

The release includes:

- `data/consistency_units_merged.csv`: Reference verdicts for 59,877 CVE–file units.
- `data/semgrep_findings.csv`: 26,033 parsed Semgrep findings.
- `data/scan_manifest.csv`: Provenance metadata for 51,468 unique source files.
- `data/hunk_ranges.csv`: 138,020 changed-hunk records.
- `data/named_graphs_cwe.trig`: CWE 4.20 hierarchy.

### Installation

Requires Python 3.12 and the dependencies listed in `requirements.txt`.

```bash
python -m pip install pandas rdflib
```

### Independent Verdict Reconstruction

From the repository root, execute:

```bash
python scripts/verify_verdicts.py
```

The script independently reconstructs exact CWE matches (EP), hierarchical matches (HP), mismatches, and no-finding verdicts for three evidence-localization regimes.

It compares the reconstructed results against the stored reference verdicts for all 59,877 evaluation units.

Expected validation result:

```text
Units checked: 59877
Verdict comparisons: 179631
Mismatched comparisons: 0
OVERALL: PASS — all verdicts reproduced
```

### Reproducibility Scope

This procedure reproduces the evaluation verdicts from released derived scanner evidence. It does not rerun Semgrep or reconstruct the complete vulnerable source-code corpus.

Full scanner re-execution requires retrieving the original source files and access to the corresponding Semgrep Pro configuration.

A documented normalization of one malformed scanner file identifier is described in `DATA_CORRECTIONS.md`.

---

## Citation

If you use this artifact in academic research, please cite:

Gupta, P., Achter, L., Eder, J., & Hof, H.-J. (2026). Provenance-Preserving Auditing of Vulnerability Labels in Large-Scale CVE-Derived Datasets. 2nd International Workshop on Assessment with New Methodologies, Unified Benchmarks, and Environments, of Intrusion Detection and Response Systems (ANUBIS 2026), co-located with ESORICS 2026.

The citation will be updated with the publisher's official bibliographic metadata when confirmed.

---
