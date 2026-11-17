# SABLE development handoff for AI contributors

Last updated: **17 November 2026** (Asia/Karachi), after Hamzah's analysis push.

Read this entire file before planning changes. Then follow the reading order below
and inspect the actual code you will change. This is a maintained handoff, not proof
that the repository cannot have changed since the last update. Reconcile discrepancies
with current code and the user's instructions; do not silently discard their decisions.
Update this file and README.md after material implementation or status changes.

## 0. Latest change: Hamzah's analysis push (17 November 2026)

Read this first if you last worked on the repository before 17 November.

**New (Hamzah's guide scope, pages 8-10):**
- `sable/kb/`: `data/meta.yaml`, `binaries.yaml` (42 GTFOBins entries),
  `cves.yaml` (18 local privilege-escalation CVEs), `rules.yaml` (15 rules with fix
  and rollback templates, ATT&CK IDs); `kb.schema.json`; `loader.py`
  (`load_kb`, errors name file and field); `versions.py` (dpkg version comparison).
- `sable/graph/build.py`: `analyze(snapshot, config)` -> validated `stage: analysis`
  results; `build_graph`, `GraphBuilder` (refuses edges without evidence).
- `sable/graph/paths.py` and `sable/score/goal.py`: path enumeration, bands and goal
  scoring **moved here** from `sable/fix/paths.py` (code unchanged).
  `sable/fix/paths.py` re-exports them and keeps `residual_risk`, so existing imports work.
- `sable/score/likelihood.py` (base x strength factor, CVSS base) and
  `sable/score/voi.py` (`compute_voi`, NV-01).
- `docs/ANALYSIS.md`: interfaces, rule format, scoring, VOI and the acceptance matrix.
- Tests: `tests/test_kb.py`, `tests/test_analysis.py`, `tests/test_voi.py`,
  `tests/analysis_helpers.py` (110 new tests; 171 in total).
- `tests/fixtures/regenerate.py` / `make fixtures`; `config/scoring.yaml` gains
  `goal_exact_edge_limit`, `goal_samples`, `voi_bonus: 0.1`; `pyproject.toml` packages
  the KB data; a `.gitignore` was added (this handoff previously claimed one existed; it did not).

**Changed in other members' areas, and why:**
- All `tests/fixtures/results/*.json` and `terminal_weak3.txt` are now **generated
  by the analyzer** from the unchanged snapshots (decision agreed with Hamzah). They
  serialize with `dumps()` (sorted keys), so the diff is large. Structure and IDs
  are kept: same edges/paths/fixes; `kb_version` is now `1.0.0` with `kb_date`;
  credential node `cred:db` is now `cred:/var/www/config.php`; fix text comes from
  the KB templates (e.g. weak3's capability fix is `setcap -r /opt/python`). All of
  Thomas's existing tests pass unchanged against them; none of their expected values
  were edited. The completed fixtures now also carry VOI (empty where no unknowns).
- Windows compatibility only, no behaviour change: `read_text()` calls in
  `sable/cli.py`, `sable/contracts/validation.py`, `sable/report/html.py` and the tests
  now pass `encoding='utf-8'` (Windows defaulted to cp1252 and failed 11 reporting
  tests). `tests/test_installation.py` uses the `sable.exe` launcher on Windows.

**Decisions taken (also in DECISIONS.md / CONTRACTS.md):**
- One confidence definition: analysis, planner, residuals and VOI share
  `graph/paths.py` + `score/goal.py`. NetworkX is not used; the guide's
  `all_simple_paths` would merge parallel edges from different rules.
- Unknowns need real evidence **plus** a missing check: an interactive account
  (user_account, uid >= 1000, login shell) without recorded sudo rules, when
  `sudoers_full` is missing, gets an `unknown` edge to root with `unknown_id`.
- Credential reuse is an `inferred` rule (cred -> interactive account), fired only
  when user_account evidence exists. weak1's synthetic snapshot has none, so its
  results still stop at the credential and Thomas's "no dbadmin" test holds.
- Default goals: root, every reachable asset/credential node, configured asset_goals.
- `voi_bonus` default 0.1. VOI uses `plan_fixes` (with exact disabled for speed).
- `sable analyze` and VOI wiring into the CLI are **left to Thomas**.

## 1. User intent and confirmed scope

The user is Thomas, working on SABLE for CS3002 Information Security, Fall 2026,
Group 4. The intended application accepts one target Linux server's SSH credentials
and outputs a complete security report. It collects facts read-only, builds an
attack graph, scores routes to root/sensitive assets, recommends reversible fixes,
and provides HTML and terminal reporting. The minimum product is a Python CLI.
A web frontend, external AI service, database, scheduler and multi-host service are
not part of the confirmed architecture.

Two PDFs conflict:

- `SABLE_Developer_Guide.pdf` describes collection, knowledge-base rules, attack graphs,
  confidence scoring, fix optimisation, remediation, reports and four lab targets.
- `SABLE_Feature_List.pdf` v2 explicitly replaces graph/scoring/optimisation with Gemini
  assessment and a formula-based server rating. It also changes feature IDs and targets.

Thomas explicitly chose **the developer guide: graph, fixes, reports** after this
conflict was explained. Use that guide as primary; the feature list is fallback only
where compatible. Do not introduce Gemini, substitute a server rating for graph
confidence, or reduce the four targets to two because the other PDF says so.
Consult the actual PDFs before implementing a feature; this file is not their replacement.

The work began with Thomas asking whether he could start before the other members.
He then requested shared schemas and setup, followed by his fix-planning and report
modules against an existing graph. Those features were implemented without building
the collector or evidence-to-graph generator. Thomas subsequently requested contextual explanations in the HTML report and
consolidation of application disclaimers at its end. Those changes are implemented;
no claim of completing the whole application has been made.

Hamzah (KB, attack graph, scoring, VOI owner) then implemented his developer-guide
scope on 17 November 2026 (section 0), working on Windows. He asked that commits are
authored by him only (git user Hamzahrana, no AI co-author lines) and that nothing is
pushed without his explicit instruction.

## 2. Read the repository in this order

1. README.md for user-facing functionality and commands; this file for context.
2. Developer guide: pages 1–3 for stack/contracts/targets; the relevant owner's
   feature pages. Thomas's planning/report requirements are on pages 11–13.
3. `docs/CONTRACTS.md` and **both actual JSON Schema files** under `schemas/`.
4. One complete fixture chain: snapshot, `.analysis.json`, and completed `.json`
   under `tests/fixtures/`; inspect weak3 for two independent goals and weak1 for missing data.
5. `docs/PLANNING_AND_REPORTING.md` and `docs/ANALYSIS.md`, including their
   requirement acceptance matrices.
6. `docs/TEAM_START.md` and `docs/DECISIONS.md` for ownership and open questions.
7. Relevant Python functions, templates, tests, configuration and packaging metadata.

Inspect all applicable first-party documentation and interfaces before changing a
contract. Do not stop after reading this handoff, infer implementation from a folder
name, or treat generated reports as source. You do not need to read every byte of
vendored minified Cytoscape; inspect its version/license and the first-party wrapper.

## 3. Current state: what exists versus what does not

Working code:

| File/module | Responsibility |
|---|---|
| `sable/cli.py` | argparse commands validate, plan, report, compare; safe YAML loading; config/flag overrides; controlled errors |
| `sable/contracts/validation.py` | Structural and semantic validation; schema loading via package resources; deterministic dumps |
| `sable/fix/planner.py` | Template mapping, candidate validation, greedy selection, public planning API and full result finalization |
| `sable/fix/exact.py` | Exhaustive minimum fix count for High paths, bounded at 15 candidates |
| `sable/fix/robust.py` | Expected-set-preserving worst-case planning for represented unknown edges |
| `sable/fix/paths.py` | Residual recalculation; re-exports the shared path/goal functions below |
| `sable/kb/` | YAML catalogues (binaries, CVEs, rules, meta), KB schema, loader, dpkg version comparison |
| `sable/graph/build.py` | Rule engine: snapshot + KB + config -> graph, entries, goals, unknowns, candidates; `analyze()` |
| `sable/graph/paths.py` | Shared path enumeration over edge IDs, path confidence, bands |
| `sable/score/likelihood.py` | Step likelihood = base x strength factor, breakdowns, CVSS base |
| `sable/score/goal.py` | Shared-edge-aware goal confidence |
| `sable/score/voi.py` | NV-01 value of information using the planner |
| `sable/redaction.py` | Recursive output sanitization using known secrets and common secret patterns |
| `sable/report/html.py` | Jinja2 render and HTML/JSON/text output writer |
| `sable/report/explanations.py` | Evidence-based natural-language explanations for paths, fix impact and goal routes |
| `sable/report/terminal.py` | Pure terminal-summary formatter |
| `sable/report/compare.py` | Structural path comparison across result files |
| `sable/report/templates/` | Autoescaped HTML and first-party offline what-if JavaScript |
| `sable/report/vendor/` | Cytoscape.js 3.30.4 and MIT license |
| `schemas/` | Versioned snapshot/results JSON Schemas, installed as package resources |

Scaffolding, not implementations: `sable/collect/`, `sable/remediate/`. Their
package files do not imply that SSH collection or apply/rollback works.
`targets/` and `tests/integration/` currently contain guidance, not Docker targets
or a working live integration harness.

Other assets: pyproject.toml, Makefile, public YAML defaults, .gitignore, four
synthetic snapshots, eight analysis/completed results generated from them by
`tests/fixtures/regenerate.py`, a terminal-output fixture, Python tests and a
separate browser check. No `.github/workflows` file is tracked in git, despite the
earlier note about a CI workflow; add one if CI is wanted.

Thomas's original path/scoring code was moved, unchanged, into `graph/paths.py`
and `score/goal.py` and is shared by analysis, planning, residuals and VOI. Do not
create conflicting probability definitions.

## 4. Ownership and intended end-to-end flow

| Member | Main responsibility | Handoff |
|---|---|---|
| Mishaal | SSH collection, read-only safety, audit logs, targets and integration harness | Validated redacted snapshot, missing checks, certificate data |
| Hamzah | KB catalogues/rules, evidence-to-graph generation, scoring, VOI | Analysis results, concrete candidate fixes/templates, represented unknowns |
| Thomas | Fix planning, remediation, HTML/terminal reports, CLI orchestration | Completed results and report files; future separately gated remediation |
| Shared | Schemas, redaction integration, fixtures, acceptance tests and review | Producer/consumer agreement |

Target flow:

```text
SSH credentials (memory only)
  -> read-only collector -> redacted snapshot.json
  -> KB/graph/scoring -> results with stage=analysis
  -> fix planning + residual analysis + VOI orchestration
  -> results with stage=complete -> report.html + results.json + summary.txt
```

Hamzah's NV-01 (`compute_voi`) calls Thomas's pure planner for alternate unknown
scenarios. The planner must not call VOI: that creates a dependency cycle. The
orchestrator populates VOI after `finalize_results` (which preserves any supplied
list and does not calculate it); the CLI does not do this yet, so reports made via
the current CLI honestly say no VOI ranking was supplied. Optional remediation is a separate explicitly requested action,
never an implicit side effect of scan/report.

## 5. Contract details you must preserve

Schemas use Draft 2020-12 and `schema_version: "1.0"`. Objects generally reject
unknown fields. The guide's JSON was illustrative; these implemented schemas are
the executable contract. Do not copy its ellipses into real JSON or silently loosen
validation to make malformed data pass.

### Snapshot

Required top-level fields: schema_version, meta, evidence, missing, no_writes.
Metadata includes host, distro, kernel, user, groups, mode, timestamp and sable_version;
architecture/uptime are optional. Preserve the original scan time and account.

Evidence records contain id, type, typed data, source_cmd and strength. Supported types:
suid_binary, file_permission, sudo_rule, scheduled_job, service, capability,
credential_location, user_account, ssh_setting and package. Read the schema for
exact per-type fields. source_cmd is an allow-list ID, not arbitrary command text.
Strength is observed, inferred or unknown. Credential evidence stores location and
pattern metadata, never the secret value or raw matched output.

Missing checks record check/reason and optional detail. No-writes has status,
method, expected_changes and unexpected_changes. `not_run` with method `none`
means no verification happened. Never turn it into `passed` because no changes
were recorded; a passing certificate needs an actual method and no unexpected changes.

### Results and stage boundaries

Results embed the original evidence, missing checks and certificate, and add
kb_version to metadata (optional kb_date is supported). Reporting must not require
SSH or a separate raw evidence file. Graph nodes and edges, paths, goals, unknowns,
VOI, fix_candidates, fixes, fix_sets and residual are all present.

- `stage: analysis`: fixes and VOI are empty, greedy is empty, exact/robust and
  residual are null. Candidate fixes may already be populated.
- `stage: complete`: residual is an object, even if no paths remain. fixes lists
  selected greedy fixes, in selection order; fix_candidates lists all options.
- fix_sets.greedy/exact/robust contain **candidate IDs**. An exact/robust option need
  not be in the greedy-selected fixes list.
- Optional solver `null` means not computed/no solution as qualified by diagnostics;
  `[]` means it computed an empty selection. Never conflate these.
- Optional planning diagnostics contain exact_status, High-only greedy selection,
  breakable risk, risk curve, confidence thresholds and path cutoff.
- Edge cis and attack tags are displayed when supplied. The reporter does not invent them.

IDs must be unique and references must resolve. Paths contain ordered edge IDs,
are connected/simple and end at the declared goal. Edge likelihood equals base ×
factor, and path confidence equals the product of its edge likelihoods. Keep
fix-to-edge and edge-to-evidence links intact. Ranked fixes must match their candidate
records except for added risk_removed. Residual paths cannot use removed edges.

Call `validate(data, kind, snapshot=source_snapshot)` when applicable; JSON Schema
alone does not verify cross-record links. Validation also does not prove evidence
is true, all attack paths were found, a target is secure, or every secret was removed.
Use `dumps()` for stable object-key serialization and rejection of non-finite JSON
numbers. Sort unordered collections explicitly, but preserve path edge order and
fix ranking. Do not add analysis timestamps that break repeatability.

For schema changes, update the actual schema, producers, consumers, fixtures,
validation and meaningful tests together. Coordinate producer/consumer changes;
breaking changes need a new version and migration strategy. Optional additions still
require compatibility consideration because old schemas reject unknown properties.

## 6. Reuse the current APIs and algorithms

```python
from sable.graph.build import analyze          # snapshot -> stage=analysis
from sable.score.voi import compute_voi        # ranked VOI list
from sable.kb.loader import load_kb
from sable.fix.planner import build_candidates, plan_fixes, finalize_results
from sable.report.html import render_html, write_report
from sable.report.terminal import terminal_summary
from sable.contracts.validation import validate, dumps
from sable.redaction import redact

plan = plan_fixes(graph, paths, {"fix_candidates": candidates})
analysis_results = analyze(snapshot, settings)
complete = finalize_results(analysis_results, settings)
complete["voi"] = compute_voi(complete, settings)
outputs = write_report(complete, "output/run", secrets=session_secrets)
```

`graph` is the contract's JSON mapping, not a NetworkX object. Adapt a future
NetworkX producer at the boundary. Planning returns new data without mutating inputs
or executing commands. `plan_fixes` returns fixes, fix_sets and planning diagnostics;
`finalize_results` additionally enumerates supplied-graph paths, scores goals,
recomputes residuals, sets stage and validates the completed result.

Candidate templates are keyed by rule ID and contain type, description, command,
rollback. Only simple named placeholders are allowed, resolved against a supporting
evidence record's data plus src/dst/rule. Equal rendered fixes merge their edges.
Rules requiring joins across multiple evidence records should produce concrete
candidates upstream. Missing rollback is an error. Missing templates leave paths
unfixable; do not fabricate fixes. A `fix_templates` config mapping makes the
finalizer instantiate templates instead of using existing candidates.

Greedy optimizes the sum of remaining High/Medium path confidence, counting a path
once per removal. Tie by fix ID; stop when no eligible paths or no useful fixes
remain. This is not a probability: summed risk can exceed 1. Low and unfixable paths
remain in residuals. Exact minimizes fix count for **High only**, so its comparison
uses a separate High-only greedy run. Status is optimal, skipped_limit or uncoverable.
The A/B/C counterexample must continue giving greedy 3 versus exact 2.

Robust planning preserves the expected set, makes represented unknown edges certain
(likelihood 1), enumerates worst-case paths and adds coverage. It cannot invent
missing unknown edges. The curve's denominator is breakable High/Medium risk, not
all possible host risk; zero breakable risk must be shown honestly.

Shared path/goal defaults (`graph/paths.py`, `score/goal.py`): cutoff 6; High >= 0.6, Medium >= 0.3; goal scoring enumerates
edge states up to 16 distinct edges and otherwise uses 10,000 samples with seed 0.
Goal scoring counts shared edges once: the guide's shared-edge example is 0.48,
not 0.64. Limits are configurable. Preserve stable ordering and local fixed RNGs.

Finalizer entry defaults are supplied path entries plus the scan account; goals
are supplied goal records plus root when represented. Explicit config entries/goals
are required for scope not inferable from the supplied paths. On the analysis side,
`analyze` takes `extra_entry_points` (e.g. www-data for weak2) and `asset_goals`;
paths it produces carry those entries forward, so the finalizer picks them up.

`report` plans an analysis input, or replans when nonempty config is supplied.
Otherwise it renders a completed input as given. `plan` always replans. Config
strength_factors/unknown_prior are consumed by `analyze` (and voi_bonus by
`compute_voi`); the planner does not rebuild edge likelihoods from them. Do not
assume every YAML key is consumed by every component.

## 7. Reports, safety and resource packaging

The report includes all required sections plus expected/robust sets, exact gap,
risk curve, optional mappings and supplied next-check information. Terminal output
shows the top five paths, top three fixes and scan mode. `write_report` writes
report.html, results.json and summary.txt only after preparing/validating outputs.
Repeated exports overwrite those filenames; unique run-directory management is not
implemented. These functions never modify the target.

Retain Jinja2 autoescape and StrictUndefined. Use tojson for embedded payloads,
textContent for dynamic DOM text, and numeric index-based checkbox mapping. Never
mark evidence or host-provided strings safe. Only trusted bundled source assets
are inlined as safe script content. The CSP blocks external requests. Cytoscape is
vendored with its license; do not replace it with a CDN URL. The ResizeObserver
keeps the graph contained on mobile. Browser what-if logic blocks a path if any
edge intersects the selected fixes; it does not search for new paths in JavaScript.

Use the single shared redact() before serializing any output. It handles supplied
literal secrets, labelled password/token assignments, private key blocks, bearer
tokens, URI credentials and control characters. It cannot recognize arbitrary
unlabelled secrets. Future collection must redact before persistence and use this
helper for snapshots, logs and errors; report redaction alone is insufficient.
`--redact-env NAME` supplies known secrets without exposing their values in argv.
Do not store credentials in YAML, JSON, fixtures, exception text or debug output.

All command/rollback template strings are display/planning material today. Only
chmod/chown candidates can carry script_and_apply; sudo/service/capability/manual
are recommend_only. Even script_and_apply does not mean an executor exists or ran.
Future remediation must use a separate reviewed boundary, validate operations,
record original state first and confirm changes. Never execute arbitrary strings
from result files or weaken the collector's read-only command registry.

pyproject.toml includes schemas, templates, JS and vendor files as package data.
Load resources with importlib.resources, not repository-relative cwd assumptions.
A source checkout working is insufficient: verify the wheel and installed CLI too.

### Confirmed report-writing preference

Thomas requested short natural-language explanations tied to the actual output,
not generic security tutorials. The executive-summary yellow banner now announces
recommended fixes (or honestly states none were selected). Each path explains the
starting access, the recorded weakness and the reachable privilege/asset. Multi-step
paths preserve edge order. Unknown evidence remains conditional; unfamiliar types
use graph/rule/evidence facts without inventing an exploit mechanism.

All HTML application warnings/disclaimers belong in the final Limitations section.
Elsewhere, keep factual statuses (such as filesystem verification not_run) and use
an internal limitations link if needed. Do not reintroduce repetitive yellow warnings,
claim a certificate passed when it did not run, or claim fixes were applied. The
terminal summary was not changed by this HTML-specific request.

Explanations are built from the already-redacted payload in
sable/report/explanations.py and passed through normal Jinja2 escaping. No external
AI call, schema change or alteration to planning/scoring is involved. Tests cover
known fixtures, multi-step order, unknown/fallback wording, disclaimer placement,
empty reports and redaction/escaping of text used in explanations.

## 8. Coding and collaboration conventions

- Keep Python 3.10 compatibility even if the local interpreter is newer. Use
  snake_case functions/variables, uppercase constants, four-space indentation,
  concise module/function docstrings and plain explicit control flow.
- Match the adjacent module's style; prefer small functions and JSON-compatible
  dict/list data at boundaries. The current code is function-oriented, not a web
  framework or class hierarchy. Do not introduce a framework or mass reformatting
  merely to implement a local feature. No linter/formatter/type checker is configured.
- Keep deterministic domain logic separate from CLI/I/O. Do not print inside the
  planner, open SSH connections from reporting, or call external services in tests.
- Prefer standard-library tools and the declared stack. Update pyproject.toml and
  package-data settings when new dependencies/resources are genuinely required.
- Raise clear ContractError/ValueError at invalid boundaries; CLI failures should
  be controlled and not echo sensitive payloads. Do not hide errors by disabling
  schema checks or returning an empty apparently successful result.
- Preserve public signatures, deep-copy semantics and ID relationships. Read tests
  before changing an interface; avoid duplicating existing validators, redaction,
  scoring or serialization helpers.
- Add behavioral tests for meaningful cases and failures. Do not rewrite expected
  values merely to match a bug. Avoid tests that only mirror implementation details.
- Review current worktree changes before editing; preserve other members' work.
  Keep changes focused and document migration/compatibility consequences.
- Do not edit vendored minified code or generated output as the implementation.
  Update templates/source and regenerate examples. Retain third-party license files.

## 9. Environment, installation and regression history

**Windows (Hamzah, 17 November 2026):** the checkout is at a Windows path; Python
3.13 in `.venv` (ignored). `python -m venv .venv`, then
`.venv\Scripts\python -m pip install -e ".[dev,app]"`. The Python 3.13 venv has no
setuptools, so install `setuptools>=68` before the `--no-build-isolation` regular
reinstall below. Always pass `encoding='utf-8'` when reading/writing text files;
the Windows default (cp1252) broke report tests. git `core.autocrlf=true` stores
LF in the repository even though files written on Windows use CRLF locally.

The notes below were written on macOS:

The project is located in an iCloud-backed macOS directory with spaces in its path.
Use proper path quoting, pathlib, subprocess argument lists and package resources.
Do not hardcode the developer's absolute path in production code or tests.

Use Python 3.10+, a virtual environment, and `python -m pip install '.[dev]'`.
The optional app extra adds Paramiko/NetworkX (also lists YAML/Jinja dependencies).
No live scanner is wired to those libraries yet. Make setup installs dev+app.

An actual user failure occurred: `sable report ...` raised ModuleNotFoundError even
though imports from the project root worked. Python 3.14 startup logs showed it
skipping a hidden editable-install `.pth` registration file. Clearing hidden flags
was not durable in this environment. A **regular installation** fixed the command:

```sh
python -m pip install --no-build-isolation --no-deps --force-reinstall .
```

This assumes dependencies/build tooling are already installed. After changing code,
reinstall to refresh the installed copy; or use `python -m sable.cli ...` from the
root to exercise source. Do not claim the regular installed command automatically
reflects edits. CI uses editable installation on Linux, where this specific failure
was not observed. Do not patch sys.path in the launcher to conceal packaging problems.

`tests/test_installation.py` launches the installed script from a temporary directory
with PYTHONPATH removed and generates a real report. This catches defects that pytest's
configured source path misses. Run it after refreshing the installation when code
changes. No real credentials or target changes were involved in prior verification.

## 10. Verification history and how to verify future work

Last observed local run: **171 tests passed**, Python 3.13 on Windows 11, 17 November
2026, against both an editable and a regular installation (installed-CLI test included).
A deliberately broken KB rule made 2 tests fail (fixture drift check), confirming
the tests guard the catalogue. The wheel was checked for the KB YAML/schema files.
The README analyze example was run and wrote a report. Browser checks were not
rerun: no HTML/JS changed. Previous run: 61 tests, Python 3.14 on macOS, 14 November.
No remote CI result is asserted.
Four synthetic reports passed isolated offline browser checks with zero JavaScript
errors and zero HTTP(S) requests. Recommended fix selections matched residual counts;
clear restored original paths. Desktop/mobile screenshots were inspected. The wheel
was checked for schemas, templates, JavaScript and license resources.

Analysis tests cover every KB/AG/CS/NV-01/NV-05/NF-02/NF-05 acceptance check in
docs/ANALYSIS.md, including a positive and negative fixture per rule and a check
that committed analysis fixtures equal fresh analyzer output.
Tests cover structural/semantic contracts, malformed data, schema timestamps,
fix-template mapping, missing rollback, unsafe automation types, repeatable ordering,
exact optimality example, solver limits/uncoverable paths, unknown-edge robust sets,
cycles/cutoffs, shared-edge goal scores, confidence boundaries, redaction/XSS defenses,
HTML sections, JSON round-trip, terminal snapshot, CIS display, scan comparison,
CLI config precedence and installed-command behavior.

Typical checks after relevant code changes:

```sh
python -m pip install --no-build-isolation --no-deps --force-reinstall .
python -m pytest -q
make validate
sable report tests/fixtures/results/weak3.analysis.json --output output/demo
```

For HTML/JS/layout changes also run the optional Node Playwright script:

```sh
node tests/browser/check-report.cjs output/demo
```

Install Playwright/browser tooling separately if unavailable; BROWSER_EXECUTABLE
can point to local Chrome. The script uses an offline isolated browser, verifies
what-if counts, checks mobile overflow and saves screenshots. Inspect the images;
passing selectors alone does not prove readable layout. Repeat on relevant empty,
missing-evidence, residual-risk and unknown-edge cases as appropriate.

All fixtures are synthetic. Since 17 November the committed analysis/completed results
are generated from the snapshots (`make fixtures`); rerun it after KB, graph, scoring
or planner changes and review the diff. Planning tests also compute their own outputs. Browser screenshots/reports live in
ignored output/ and may not exist on another checkout. Regenerate them rather than
assuming they are tracked. Passing unit tests does not establish live collection,
no-writes safety, real detection accuracy, rollback correctness or distro support.

## 11. Remaining work and suggested integration order

1. Coordinate the implemented contracts with Mishaal/Hamzah. Preserve the working
   planner/report API while adding real producers; avoid starting a second schema.
2. Build collector connection/safety foundations and real lab targets. Get one
   authentic redacted snapshot through validation before broadening checks.
3. ~~KB loaders/rules and evidence-to-graph generation~~ done (17 Nov). Remaining:
   cross-check `cves.yaml` fixed versions against the Ubuntu/Debian trackers; extend
   rules when real snapshots show gaps (group-based permissions, SGID, other caps).
4. ~~Shared path/goal scoring~~ done: one definition in graph/paths + score/goal.
5. ~~VOI~~ done as `compute_voi`; Thomas's orchestration must call it after
   `finalize_results` and before rendering.
6. Thomas: add `sable analyze --snapshot` (analyze -> finalize -> VOI -> report) and
   later `scan` to connect the entire pipeline. Pass `scan.extra_entry_points` /
   `asset_goals` from sable.yaml through to `analyze`. The application
   should eventually accept SSH credentials and produce the report in one run.
7. Implement genuine no-writes fingerprint/certificate checks, error/missing-data
   behavior and source-side redaction/audit acceptance tests.
8. Implement remediation scripts/state/apply/rollback separately, with explicit
   gating and throwaway-target tests. Complete RP-05's real stat restoration check.
9. Run all target expectations, supported Python/distro tests, acceptance checks,
   review, security-analysis documentation and fresh-clone demo rehearsal.

Follow the guide's Must/Should/Could priorities. Thomas's planner/report features
include several Should/Could items already; this does not waive missing core Musts
elsewhere or authorize dropping them to call the project finished.

## 12. Open questions and known limits

- **weak1:** a readable password location does not prove reuse by dbadmin. The
  analyzer models reuse only as an `inferred` step and only with dbadmin's
  user_account evidence; the current synthetic snapshot has none, so its results stop
  at the credential. When Mishaal's real weak1 snapshot includes accounts, the
  report will show a Low cred -> dbadmin -> root path and a sudoers_full unknown;
  `test_path_explanations_use_recorded_evidence` (asserts no "dbadmin") must then be
  revisited with the team.
- **Collector contract (Mishaal):** analysis assumes `readable_by`/`writable_by` list
  user names (expand groups), kernel package evidence is named
  `linux-image-<uname -r>`, and an unreadable sudoers is recorded as missing check
  `sudoers_full`. Confirm these when real snapshots exist.
- **CVE data:** `cves.yaml` fixed versions were written without network access and
  must be verified against official trackers before evaluation.
- **AG-07 graph SVG** (Should) is not implemented; the report's Cytoscape view covers it.
- **weak2:** www-data must be enabled as an entry for its writable cron-script path.
- **Remediation boundary:** the guide's exclusive read-only SSH execution rule and
  optional write mode need distinct, explicitly gated runners. Never relax collection.
- **Capability removal:** currently recommend-only, although weak3 proposes it as a
  fix. Decide policy before generating/applying capability-changing scripts.
- **Upstream configuration:** settled by Hamzah on 17 November: voi_bonus 0.1 and a
  single shared scorer. The team may still tune values in scoring.yaml.
- **Runtime validation:** schemas and current validators do not prove semantic
  completeness, safe execution of a command string, exhaustive redaction, or real
  reversibility. Keep assertions and report wording within verified behavior.
- **Output history:** report filenames overwrite within one output directory; no
  database, saved-run manager or scheduler exists.
- **Peer review/targets:** no other-member PR review or live integration completion
  is claimed by this handoff. The guide's definition of done includes them.

## 13. Maintaining this handoff and retiring the README pointer

After a material change, update this file's date, implementation map, public APIs,
contract decisions, test evidence and remaining work. Update README.md so it states
what actually works. Do not leave stale success counts or turn a planned feature
into a completed claim. Keep docs/CONTRACTS.md and the detailed implementation guide
consistent with schema and behavior changes; record unresolved differences explicitly.

Treat the **project** as complete only when the agreed developer-guide scope has
been implemented and reviewed, all required acceptance checks have evidence, and
a fresh checkout can execute the real end-to-end workflow against the lab targets.
That includes collection/analysis/report integration, missing-data and redaction
handling, no-writes verification, required remediation/rollback checks, documented
compatibility/limitations and run instructions. Any deferred optional items should
be explicitly recorded with the team's accepted scope, not silently counted as done.

**When those completion conditions are met, remove the entire README section titled
"AI contributor handoff — temporary", including its instruction to read PROGRESS.md.**
This removal is explicitly requested by Thomas. Do not remove it after finishing a
single module, a documentation update or a passing unit-test run. At completion,
update the README to the final product status and replace any other temporary
handoff-only references as appropriate. Keep PROGRESS.md as a final historical
handoff unless the user separately asks to delete or archive it; removing the README
pointer does not itself authorize deleting the file.
