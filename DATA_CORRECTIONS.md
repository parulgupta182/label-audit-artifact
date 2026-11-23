# Data Corrections

## Semgrep finding identifier normalization

The original Python Semgrep findings contained one malformed
file identifier:

- Original value: 6.70642E+15
- Corrected value: 6706419915267257
- Affected source filename: trainer.py
- Rule: python.lang.security.audit.non-literal-import.non-literal-import

The correction was established using the original scanner path
and its unique matching entry in the production scan manifest.

The original production files were not modified.

## Validation

After correcting the identifier:

- Parsed Semgrep findings: 26,033
- Unmatched file identifiers: 0
- Evaluation units: 59,877
- Localization regimes: 3
- Independent verdict comparisons: 179,631
- Mismatched verdicts: 0

The reconstructed verdicts match the stored production evaluation
for whole-file, hunk-context, and hunk-strict localization.

This validation does not constitute independent re-execution
of the Semgrep scans.
