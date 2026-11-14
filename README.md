# SABLE: Safe Attack-Boundary & Logic Evaluator

SABLE is a Python security-assessment application being built for Linux servers.
The intended workflow is to accept SSH credentials, collect evidence using
read-only commands, build and score attack paths, plan reversible fixes, and
produce a full HTML report plus a terminal summary.

**Current progress:** offline fix planning and reporting work against a supplied
attack graph. Live SSH scanning, knowledge-base-driven graph generation and
remote remediation are not implemented yet. This is not yet a complete scanner.

## AI contributor handoff — temporary

**AI models: read [PROGRESS.md](PROGRESS.md) in full before exploring, planning,
or changing this repository, then read the referenced contracts and relevant
implementation files.** It records the project context, decisions, interfaces,
coding conventions, verification history and remaining work. Keep it current.
When the entire project meets the completion criteria in PROGRESS.md, remove this
whole temporary section from README.md. Do not remove it merely because one task
or one contributor's work is complete.

## What is implemented

| Area | Working functionality |
|---|---|
| Shared contracts | Draft 2020-12 JSON Schemas for snapshots and analysis/completed results; typed evidence, missing checks, fix candidates and no-writes status |
| Validation | Structural checks plus unique IDs, evidence/edge references, connected simple paths, confidence arithmetic, fix selections and source-snapshot preservation |
| Candidate fixes | Instantiate KB fix templates, map fixes to edges, merge identical fixes, require rollback information |
| Greedy planner | Select the largest marginal reduction in High/Medium path confidence; deterministic fix-ID tie-breaking |
| Exact solver | Find a minimum-cardinality set covering High paths for up to 15 candidates; report a comparable High-only greedy/exact gap |
| Residual risk | Remove selected edges, enumerate remaining paths and recalculate path/goal confidence on the supplied graph |
| Robust planning | Preserve the expected fix set and add coverage for represented unknown edges in the worst case |
| Risk curve | Cumulative breakable High/Medium path risk removed, rendered as inline SVG |
| HTML report | Self-contained Jinja2 report with executive summary, scan details, ranked paths and score breakdowns, evidence, fixes, residual risk, certificate status and limitations |
| Contextual explanations | Evidence-based descriptions of each attack step, affected access, fix impact and predicted residuals; application disclaimers grouped at the end |
| Interactive report | Bundled Cytoscape.js graph and fix checkboxes that preview blocked paths without executing anything |
| Exports | Schema-validated results.json, summary.txt and a printed terminal summary showing top paths, top three fixes and scan mode |
| Optional reporting | CIS tags and KB date where supplied; structural scan comparison showing added/removed paths and confidence changes |
| Output protection | Shared redaction helper, HTML escaping, safe embedded JSON and a report policy blocking external network access |
| Development setup | Installable Python package, CLI, configuration defaults, four synthetic target datasets, tests, CI configuration and interface documentation |

The planner includes path enumeration and shared-edge-aware goal scoring so it can
calculate residuals independently. It **does not generate attack edges from evidence**.
Greedy selection is a heuristic, not a guarantee of the smallest possible fix set.
All reported post-fix outcomes are predictions; nothing is applied to a server.

## What remains

| Area | Remaining work |
|---|---|
| Collection — Mishaal | SSH/password/key handling, host-key verification, read-only command allow-list, evidence checks, audit logs, authorization, timeouts and collector-side redaction |
| Targets — Mishaal, shared tests | Actual weak1/weak2/weak3/hardened Docker targets, expected findings, setup/reset commands and live integration harness |
| Analysis — Hamzah | KB catalogues/loaders, evidence-to-graph generation, upstream scoring, entry/goal configuration and value-of-information recommendations |
| Safety verification | Actual before/after filesystem fingerprinting for the no-writes certificate |
| Remediation — Thomas | Fix/rollback script generation, original-state recording, gated apply mode, rollback and post-change verification |
| Orchestration — Thomas, shared integration | Live scan and offline snapshot analysis commands connecting collection, analysis, planning and reporting |
| Final evaluation | Detection accuracy, complete target acceptance checks, real rollback checks, supported-platform testing, peer review and demo rehearsal |

A rollback description is required today, but rollback execution is not implemented.
The report displays supplied certificate/VOI data; it does not perform a filesystem
audit or calculate VOI. Synthetic fixtures are not evidence of live detection accuracy.

## Install and run

Use Python 3.10 or newer:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[dev]'

sable report tests/fixtures/results/weak3.analysis.json --output output/demo
```

Open `output/demo/report.html`. The same directory contains `results.json` and
`summary.txt`; the summary is also printed in the terminal. Without `--output`,
`report` writes these files under `output/`.

Available commands:

```sh
# Validate producer/consumer contracts.
sable validate snapshot tests/fixtures/snapshots/weak1.json
sable validate results tests/fixtures/results/weak1.json \
  --snapshot tests/fixtures/snapshots/weak1.json

# Plan from an existing graph and export completed results.
sable plan tests/fixtures/results/weak1.analysis.json --output output/planned.json

# Render completed results, or automatically plan an analysis-stage input.
sable report output/planned.json --output output/weak1

# Load scoring/planning settings; explicit flags override the file.
sable report tests/fixtures/results/weak3.analysis.json \
  --config config/scoring.yaml --path-cutoff 6 --output output/demo

# Compare two result files, without reconnecting to a host.
sable compare BEFORE_RESULTS.json AFTER_RESULTS.json
```

`scan`, `analyze`, `remediate` and `rollback` commands are future work. Current commands
return exit code 0 on success and 2 for handled input/configuration/I/O errors.

Install `.[dev,app]` when implementing Paramiko SSH collection and NetworkX analysis.
Jinja2, PyYAML, jsonschema and timestamp validation are already core dependencies.
The SSH defaults in `config/sable.yaml` are reserved for future collection; current
`plan`/`report` commands accept the scoring/planner configuration, not SSH credentials.

## Verification status

Last verified locally on **14 November 2026**:

- **61 Python tests passed**, covering contracts, planning, reporting and the installed CLI.
- The guide's exact-solver example produces greedy size 3 versus exact size 2.
- All four synthetic target reports passed isolated offline browser checks with no
  JavaScript errors or HTTP(S) requests; selecting recommended fixes matched residual predictions.
- Desktop/mobile layouts were inspected, including the graph resize correction.
- The built wheel was checked for packaged schemas, HTML/JS templates, Cytoscape.js
  and its license.

These are local results, not a claim that GitHub CI or live target tests have run.
CI is configured for Python 3.10 and 3.12; the latest local environment used Python 3.14.

```sh
python -m pytest -q
make validate
```

Optional browser verification uses Node with Playwright installed:

```sh
node tests/browser/check-report.cjs output/demo
```

Set `BROWSER_EXECUTABLE` to a local Chrome binary if needed. The test saves desktop
and mobile screenshots beside the generated report. See the
[implementation guide](docs/PLANNING_AND_REPORTING.md) for acceptance coverage.

## Development and installation notes

A regular installation runs the installed package copy. After source changes:

```sh
python -m pip install --no-build-isolation --no-deps --force-reinstall .
```

During development, run current source from the project root without reinstalling:

```sh
python -m sable.cli report tests/fixtures/results/weak3.analysis.json
```

In this macOS workspace, editable installation failed because its `.pth` registration
file was marked hidden and Python skipped it. A regular installation fixed the
`sable` command. Use the installation command above rather than relying on clearing
file flags. Dependencies must already be installed when using `--no-deps`.
The installation test invokes the installed CLI outside the project directory so
pytest's source-path configuration cannot hide this problem.

`make setup` installs `.[dev,app]`; `make test` and `make validate` use the active
Python. Override `PYTHON` if needed. No formatter or linter is currently configured.

## Requirements, ownership and documentation

Thomas confirmed the **developer guide's attack-graph, fix-planning and reporting
design** as the project scope. The feature list v2 describes a conflicting
Gemini-based replacement; use it only for compatible fallback information.
Do not combine its replacement architecture with this project without an explicit
scope change.

- [Developer guide](SABLE_Developer_Guide.pdf): primary feature and acceptance requirements.
- [Feature list](SABLE_Feature_List.pdf): compatible fallback information only.
- [Team starting guide](docs/TEAM_START.md): Mishaal/Hamzah/Thomas responsibilities.
- [Data contracts](docs/CONTRACTS.md): shared formats and handoff rules.
- [Planning and reporting](docs/PLANNING_AND_REPORTING.md): APIs, configuration and acceptance status.
- [Decisions](docs/DECISIONS.md): scope and unresolved integration questions.

Never commit SSH passwords, private keys, API tokens, real sensitive snapshots or
unredacted logs. Generated reports belong under ignored `output/`. Committed fixtures
are synthetic and use reserved `example.test` hostnames. Output redaction supplements,
but does not replace, removing secrets inside the future collector before persistence.
