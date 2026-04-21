# ast-grep known issues

Per-rule baselines of currently-known violations. One YAML file per rule that
has at least one violation in the tree; filename is `<rule-id>.yml`.

`check.astgrep` subtracts these entries from each scan so only NEW violations
fail CI. To refresh the baseline after fixing (or intentionally introducing)
violations, run:

    make -C build astgrep-known-issues

The directory is regenerated deterministically — do not hand-edit. Entries in
a file for which no current violation matches are silently ignored, so stale
entries never break CI; they are cleaned up on the next regeneration.

See `../ignore_known_issues.py` for the filter implementation.

## Severity interaction

This suppression mechanism only works for rules declared `severity: warning`.
`ast-grep scan` exits non-zero on any `severity: error` match regardless of
the baseline, and `set -o pipefail` on the CI command then fails the pipeline
before `ignore_known_issues.py` gets a chance to subtract known entries. A
rule promoted to `error` is therefore zero-tolerance: new violations must be
fixed (or the rule's exclusion regex extended), not baselined.
