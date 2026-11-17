# Initial decisions and remaining integration questions

## Baseline established

- Confirmed by Thomas: use the developer guide (attack graph, fix planning, and
  reports). Use the feature list only for compatible fallback details; its Gemini
  replacement is not the selected scope.
- Product entry point will be one `sable scan user@host` command accepting a port,
  key path or password prompt, and output location; it will collect, analyse, plan,
  and render. The current CLI validates contracts, plans fixes, renders reports and compares scans.
  No live scan is implemented.
- Preserve host-key verification, read-only collection, no stored credentials and
  separate explicit remediation. No network requests or target changes during setup.
- Python 3.10+ package, Draft 2020-12 JSON Schema, pytest, installed schema resources.
- Fill guide gaps with typed evidence, self-contained results, candidate fix handoff,
  explicit stage status, and a no-writes certificate status that can be not_run.
- Schema version 1.0 is the initial project baseline; it does not claim the PDFs'
  illustrative JSON already implements these additional fields.

## Review before implementing dependent features

1. weak1: credential presence does not prove reuse by dbadmin. Agree on non-secret,
   non-exploitative supporting evidence, or revise the expected chain. Do not fake it.
2. SSH execution boundary: the guide's single read-only exec_command restriction
   conflicts with optional remote apply mode. Define a separate, explicitly gated
   remediation runner before implementation; never weaken the collector allow-list.
3. Approve the proposed fix-candidate handoff and planner signature in CONTRACTS.md.
4. Confirm goal-confidence thresholds/Monte Carlo limits and VOI bonus magnitude
   before Hamzah implements them. They are not invented as contractual constants.
5. Decide whether capability fixes ever belong in generated scripts. This baseline
   restricts automation to chmod/chown; it cannot silently execute arbitrary templates.

Reviewing these choices does not block fixture-based report, parser, collector or
planner development. The initial schema files are the concrete proposal for review.
