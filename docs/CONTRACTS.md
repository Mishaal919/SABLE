# Shared contracts v1.0 (initial team baseline)

Thomas confirmed the developer guide's graph, fixes, and reports design as the project scope. The feature list v2 describes
an incompatible Gemini-based replacement. We have not silently combined the two.
The project implements these data boundaries plus offline planning and reporting;
SSH scanning and graph generation are separate integration tasks.
See DECISIONS.md for scope questions. All fixtures are synthetic, not measured scans.

## Pipeline and ownership

1. Mishaal collects and redacts evidence, then writes a validated snapshot.
2. Hamzah consumes it, builds the graph, scores paths, and emits results with
   `stage: analysis`, including `fix_candidates` instantiated from KB templates.
3. Thomas's planner consumes graph, paths, config and the candidate mapping. It
   chooses fixes, computes marginal risk and calls Hamzah's analysis functions for
   residual paths/goals. Hamzah's VOI function calls the same planner on alternate
   scenarios. The planner must not call VOI, preventing recursive dependencies.
4. The orchestrator combines these outputs into `stage: complete` results, then
   Thomas's reporter renders the full HTML report.

Both stages use results.schema.json. `analysis` must have empty `fixes`, `voi`,
empty greedy selection, null optional selections and null residual. `complete`
requires a residual object, even for a clean host. `fixes` contains the selected
fixes in greedy order; `fix_candidates` contains all candidates. Each exact/robust
selection refers to candidate IDs, not necessarily to the greedy selection.
`null` means an optional solver did not run; `[]` means it ran and selected none.

## Files and validation

- schemas/snapshot.schema.json: collector output.
- schemas/results.schema.json: analysis and complete output.
- tests/fixtures/snapshots/: four synthetic collector examples.
- tests/fixtures/results/: corresponding analysis and complete handoffs.

All objects reject unrecognised fields. Adding fields requires a schema update,
fixture, tests, and review by the producer and consumer. Breaking changes require
a new schema_version; do not casually modify the meaning of an existing field.
JSON Schemas check structure. `sable.contracts.validation.validate` additionally
checks unique IDs, references, connected simple paths, confidence arithmetic,
fix selections, residual blocked edges and preservation of the source snapshot.
It does not certify that evidence is true, detect every secret, execute commands,
or verify that an omitted attack path should have been found.

## Collection

Metadata records the original scan time (RFC 3339 with timezone); analysis must
not overwrite it. Results copy snapshot metadata and add kb_version. Both results
stages embed the redacted evidence, missing checks and no-writes certificate, so
reporting needs no SSH connection or separate raw-output file.

Evidence types: suid_binary, file_permission, sudo_rule, scheduled_job, service,
capability, credential_location, user_account, ssh_setting, package. Their data
fields are explicitly typed in the schema. An absent item is not proof of safety:
record inaccessible checks in `missing`, with a reason. Do not fabricate metadata
when identity collection fails: fail the scan clearly if required identity is unavailable.
`source_cmd` is the allow-list command ID, never arbitrary command text.
Suggested initial IDs are system_identity, suid_find, sensitive_permissions,
sudo_rules, sudoers_full, scheduled_jobs, services, file_capabilities,
credential_scan, user_accounts, ssh_settings, installed_packages.
Mishaal owns the actual fixed command registry and audit log implementation.

Passwords and key contents exist only in memory. Secret detection records path,
line and pattern type, never the matched value. Collector redaction precedes any
write. Every output writer must also use the shared sable.redaction.redact implementation. Schema validation alone is not a redactor; even allowed strings can contain
secrets. No raw stdout field is provided. Explicitly review new evidence types.

`no_writes.status: not_run` with method `none` is honest until fingerprinting is
implemented. A passing certificate requires a real method and no unexpected
changes. Never label an untested scan as passed.

## Graph, scores and planning

IDs are opaque, unique within each collection, stable for repeated analysis of the
same snapshot. Prefixes ev-, e-, p-, f-, u- are conventions, not parsing rules.
Nodes use privilege/asset/credential kinds; e.g. user:auditor, root, asset:/etc/shadow.
All edges reference evidence. Unknown-dependent edges additionally use unknown_id.
A missing check alone does not create an escalation edge.

Edge likelihood = breakdown.base * breakdown.factor. Path confidence is the
product of edge likelihoods, assuming independent steps. Goal confidence must
account for shared edges, not sum path probabilities. Bands come from scoring.yaml.

Implemented planner API remains `plan_fixes(graph, paths, config)` from RP-02.
For this interface, graph is the JSON graph mapping and config contains validated
`fix_candidates` plus scoring defaults. Return a plan mapping containing `fixes`, `fix_sets` and `planning` diagnostics.
`finalize_results` separately recomputes residuals and produces complete results.
See PLANNING_AND_REPORTING.md for configuration and KB-template integration. Team members may introduce
internal NetworkX objects, but adapters must preserve the JSON contract.

Define greedy risk as the sum of confidence of the original High/Medium paths.
A fix removes a path once if it blocks any edge; never count the same path twice.
Marginal risk is therefore nonnegative and may exceed 1 across multiple paths.
It is a prioritisation measure, not the probability of compromise. Pick maximum
marginal reduction, tie by fix ID; stop when none of the eligible paths remain
or no candidate makes progress. Report remaining paths honestly.

Exact minimises fix count for High paths as the guide specifies. A greedy/exact
size comparison must rerun greedy on that same High-only population. Robust must
include unknown-dependent edges and preserve the expected greedy set before adding
fixes, satisfying the guide's inclusion acceptance check. Exact/robust are optional.

Every candidate includes a rollback description/template. Only chmod/chown types
may be automated in this baseline; sudo/service/capability/manual are recommend-only.
This deliberately leaves capability removal as a recommendation until execution
policy is agreed. `command` strings are display/template material, not executable
instructions for an SSH runner. Implementers must construct allowed operations
with safe argument handling and record original owner/mode before changes.

Sort non-ranked collections by ID (missing by check/reason, groups lexically).
Preserve path edge order and greedy ranking. Serialize with dumps() for sorted
object keys and no non-finite numbers. Optional graph image/HTML never changes JSON.

## Fixture limitations

weak1 demonstrates readable credentials and an unavailable sudoers check. It does
not claim credential reuse or a root chain: the guide supplies no safe evidence
contract proving reuse. weak2 requires www-data as an extra entry. weak3 contains
capability and shadow paths. hardened is a clean synthetic example. Committed complete
fixtures are hand-authored examples. The planner tests independently compute
completed results and test the guide's exact-solver counterexample.
Before integration, Mishaal must supply actual snapshots and expected.yaml for each
lab target and the team must resolve weak1's missing evidence model.
