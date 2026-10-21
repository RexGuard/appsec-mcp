# Evidence tiers, attack chains and false positives

## Evidence tiers

A scanner's severity is a guess. AppSec MCP sets the final severity in code, from the evidence
behind each finding (`src/appsec_mcp/analysis/evidence_gate.py`).

| Tier | Meaning |
|---|---|
| `pattern` | One rule matched and nothing else backs it up |
| `reachable` | The match is in a file that serves routes or is an entry point |
| `corroborated` | Two or more scanners found the same file, line and weakness |
| `confirmed` | A precise detector reported a fact: a known-vulnerable package version (OSV), a secret found by gitleaks or in a provider's key format, or a committed `.env` |

In precision mode (the default) the gate applies two rules:

1. **Critical needs proof.** A critical finding at the `pattern` tier is ranked high instead.
2. **Test code does not ship.** Anything below `confirmed` that lives only in tests, examples or
   fixtures is ranked low. A real secret in a test file still counts in full.

`explain_finding` shows the tier, the scanner's original severity (`reported_severity`) when the
gate changed it, and a plain-language reason for every decision. `scan_project` reports how many
findings were `demoted`. Set `APPSEC_MCP_PRECISION=0` to keep the scanners' severities; tiers are
still recorded.

## Attack chains

`get_attack_chains(scan_id)` links findings to the system map:

- **Outside input to injection**: a route or entry point in the same file as an injection, XSS,
  path traversal or SSRF finding, and what it reaches (the data stores and services that code
  uses). XSS chains also include missing security headers when that was found.
- **Leaked key to service**: a hard-coded secret in code that calls an external service. When the
  key's provider matches the service (a Stripe key next to `api.stripe.com`), the chain is
  verified.
- **Vulnerable dependency in a served app**: a high or critical OSV advisory in an app with routes.
  Whether a request reaches the vulnerable code is not proven, so this is always a hypothesis.

A chain is as strong as its weakest finding: `verified` (all corroborated or confirmed),
`likely` (all at least reachable) or `hypothesis`. Hypothesis chains are capped at medium.

## False positives

When a finding is wrong, `mark_false_positive(finding_id, reason)` records it for that project.
Later scans hide it, leave it out of the score, and report the number hidden as `suppressed`. It is
matched by fingerprint (rule, file and code), so if the code on that line changes it is checked
again. `unmark_false_positive` undoes it and `list_false_positives` shows them all with reasons.

## Precision benchmark

`tests/test_golden_precision.py` scans every vulnerable fixture and fails if any critical finding
is not one of the issues planted in its `expected.json`.
