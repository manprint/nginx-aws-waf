# nginx AWS WAF — Audit register

## Open audit
none

## Historical reports
| ID | File | Date | Original verdict | Original counts | Auditor |
|----|------|------|------------------|-----------------|---------|
| V001 | verify/verify_001_2026-11-27.md | 27-11-2026 | FAIL | 0 BLOCKER, 1 MAJOR, 1 MINOR | agent-1:opus |

Verdicts: PASS, PASS WITH FINDINGS, FAIL, INCOMPLETE. Historical counts/verdicts
are not recomputed as findings are fixed; current unresolved findings are below.

## Findings
| ID | Severity | Title | Current status | Closed by / date | Evidence |
|----|----------|-------|----------------|------------------|----------|
| V001-F1 | MAJOR | CRL publish overwrites the live ingress CRL with a foreign CA's | OPEN | — | V001 §F1 |
| V001-F2 | MINOR | 3.3 double completion commit + history.md rewritten in place | OPEN | — | V001 §F2 |

Statuses: OPEN, FIXED, ACCEPTED (user decision), OBSOLETE (reason recorded).
Never silently remove a finding. Update the source report's resolution too.

## Open blockers
none
