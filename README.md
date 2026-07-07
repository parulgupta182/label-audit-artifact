# Anonymous Artifact: Provenance-Preserving Vulnerability-Label Auditing

This artifact accompanies a paper on provenance-preserving vulnerability-label auditing for CVE-derived datasets.

The artifact contains:
- scripts for CVE/reference collection, patch extraction, CWE ontology construction, materialization, Semgrep finding parsing, and CWE-consistency evaluation;
- small anonymized sample data for sanity checks;
- aggregate result tables used in the paper.

The full corpus of materialized source files is not included. The artifact provides aggregate results and sample inputs sufficient to inspect the analysis pipeline and reproduce the reported tables from parsed finding/evaluation files.

## Main reported result files

`results/construction_counts.csv`  
Dataset construction statistics.

`results/scan_config.csv`  
Per-language Semgrep configuration and scan status.

`results/cwe_ontology_metadata.csv`  
CWE catalog metadata used for hierarchical matching.

`results/evidence_bearing_results.csv`  
Whole-file agreement over evidence-bearing units.

`results/localization_results.csv`  
Agreement under whole-file, hunk-context, and hunk-strict localization regimes.

`results/figure_table_inputs.csv`  
Normalized localization-retention values used for the optional localization-decay plot.

`results/table_results/coverage_by_language.csv`
Coverage of CWE-mapped evidence by language (paper Table 2).

`results/table_results/shuffled_label_baseline.csv`
Shuffled-label chance baseline, 200 permutations per language (paper Table 3).

`results/table_results/hp_direction_whole_file.csv`
Direction of hierarchy-aware matches under whole-file matching (paper Table 4).

`results/table_results/provenance_tier_whole_file.csv`
Whole-file agreement by resolved provenance-confidence tier (paper Table 6).
Mixed-confidence duplicate join keys are resolved deterministically: a unit
is high-confidence if any of its references is high-confidence.

## Manual mismatch audit

`manual_audit/mismatch_audit_cases.csv`
Per-case results of the manual audit of 44 sampled whole-file mismatch units
(paper Section 5.3 and Appendix A): unit provenance, verdicts under all three
localization regimes, the strongest-localization finding, assigned category
(C1-C5 as defined in the paper), one-line justification, and a
full-file-deletion flag. Stratified by language, minimum five units per
language, fixed seed 42.

## CWE version

The reported EP/HP results use MITRE CWE List Version 4.20, dated 2026-04-30.

## Semgrep configuration

Completed scans used Semgrep 1.166.0 with `p/default` and the `--pro` flag.
C used wrapper-based 200-file chunks. Python, Java, and C++ used direct 500-file batch-directory scans with one JSON output per batch.

## Reproduction note

The included sample data is intentionally small and anonymized. Full reproduction of the paper's corpus requires re-running the collection and materialization pipeline against NVD/GitHub and Semgrep Pro, which may require API credentials, network access, and a Semgrep Pro login.
