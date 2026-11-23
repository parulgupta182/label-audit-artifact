# Provenance-Preserving Auditing of Vulnerability Labels in Large-Scale CVE-Derived Datasets

**Research Artifact — ANUBIS 2026 (ESORICS 2026 Workshops)**

**Authors:** Parul Gupta, Lea Achter, Julienne Eder, Thomas Hutzelmann, and Hans-Joachim Hof

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

The repository provides analysis scripts, anonymized sample data, and aggregate experimental results.

**Reproducibility scope:** The full materialized source-code corpus is not distributed. Reproducing the complete analysis requires reconstructing the dataset from its original sources and executing the static-analysis pipeline. Some stages require external services, API credentials, and Semgrep Pro access.

---

## Citation

If you use this artifact in academic research, please cite:

Gupta, P., Achter, L., Eder, J., & Hof, H.-J. (2026). Provenance-Preserving Auditing of Vulnerability Labels in Large-Scale CVE-Derived Datasets. 2nd International Workshop on Assessment with New Methodologies, Unified Benchmarks, and Environments, of Intrusion Detection and Response Systems (ANUBIS 2026), co-located with ESORICS 2026.

The citation will be updated with the publisher's official bibliographic metadata when confirmed.

---
