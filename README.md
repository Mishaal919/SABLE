# SABLE: Safe Attack-Boundary & Logic Evaluator

SABLE is a Python security-assessment application being built for Linux servers.
The intended workflow is to accept SSH credentials, collect evidence using
read-only commands, build and score attack paths, plan reversible fixes, and
produce a full HTML report plus a terminal summary.

**Current progress:** the full pipeline works end to end. `sable scan user@host`
collects evidence read-only over SSH, the knowledge base builds a scored attack
graph with unknowns and candidate fixes, planning/VOI/reporting run on top, and
`remediate`/`rollback` generate and apply reversible chmod/chown fixes. This was
verified **live** against the Docker lab targets (`make targets-up`, incl. ubuntu
24.04 and debian:12), including the NV-02 no-writes certificate, a full
apply→rescan→rollback cycle, the AG-07 top-paths graph SVG, and a cross-check of the
key CVE fixed-versions against the official trackers. The only remaining item is the
team's human peer review of the pull request.

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
| Knowledge base | YAML catalogues: 42 GTFOBins binaries, 18 local privilege-escalation CVEs with Debian/Ubuntu version ranges, 15 misconfiguration rules with fix/rollback templates and ATT&CK IDs; schema-validated loader that accepts drop-in rule files |
| Attack-graph analysis | `analyze(snapshot)` builds evidence-linked edges, configurable entry points and goals, possible-entry services, unknown steps for unreadable sudoers, scored paths and candidate fixes, deterministically |
| Scoring | Step likelihood = base x evidence-strength factor with stored breakdowns; CVSS-derived CVE bases; path products; shared-edge goal confidence; configurable bands |
| Next best check | Value of information per unknown, using the planner to detect top-fix changes |
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
| Collection (Mishaal) | Read-only SSH collector: frozen command allow-list and single `exec_command` gateway, audit log, authorisation prompt, host-key-verified paramiko connection, EC-03..EC-12 evidence parsers, source-side credential redaction, deterministic schema-valid snapshots, unprivileged/elevated modes, timeouts and a `python -m sable.collect` runner |
| Remediation (Thomas) | Fix/rollback script generation (chmod/chown only; sudo/service/capability/manual kept recommend-only), original-state recording to `state.json`, gated apply mode with per-change confirmation, rollback restoration and rescan-vs-prediction compare; operations are parsed and validated, never executed as raw command strings |
| End-to-end CLI (Thomas) | `validate / analyze / scan / plan / report / remediate / rollback / compare`; `analyze` and `scan` run the full pipeline (collect →) analyze → finalize → VOI → report, with VOI now wired into the CLI |
| No-writes certificate | NV-02 fingerprint/certificate logic: docker-diff and hash comparison, allow-listed expected changes, unexpected-write flagging (live diff pending Docker) |
| Lab targets (Mishaal) | weak1/weak2/weak3/hardened with Dockerfile, authored snapshot and expected.yaml; docker-compose (ports 2221-2224) and `make targets-up/reset`; offline integration harness with a break-a-rule meta-check |
| Development setup | Installable Python package, CLI, configuration defaults, four synthetic target datasets, tests, CI configuration and interface documentation |

The analyzer generates attack edges only from catalogued rules and cites the
evidence for each; the planner and reporter consume that graph. Path enumeration
and goal scoring are shared by analysis, planning and residual risk. See
[docs/ANALYSIS.md](docs/ANALYSIS.md).
Greedy selection is a heuristic, not a guarantee of the smallest possible fix set.
All reported post-fix outcomes are predictions; nothing is applied to a server.

## What remains

| Area | Remaining work |
|---|---|
| Collection — Mishaal | Implemented and **verified live**: `sable scan` over SSH produced the expected findings on all four Docker targets |
| Targets — Mishaal, shared tests | Implemented and run live via `make targets-up` (ports 2221-2226, incl. ubuntu 24.04 + debian:12 compat targets for NF-03); offline harness also passes |
| Analysis — Hamzah | ~~AG-07 graph SVG, CVE version cross-check~~ done (static top-paths SVG in the report; key CVEs verified against trackers, two jammy kernel values corrected). Remaining: verify the pre-22.04 CVE entries and CVE-2022-2588 (tracker was down) |
| Safety verification | Actual before/after filesystem fingerprinting for the no-writes certificate |
| Remediation — Thomas | Implemented and **verified live** on weak2: apply → rescan (path gone) → rollback → rescan (path back), stat identical |
| Orchestration — Thomas | Implemented and verified live; VOI wired into the CLI |
| Final evaluation | Live detection accuracy, target acceptance, apply/rollback and NV-02 all verified. Remaining: 24.04/debian:12 base images, peer review and a fresh-clone demo rehearsal |

A rollback description is required today, but rollback execution is not implemented.
The report displays supplied certificate/VOI data; it does not perform a filesystem
audit. VOI is calculated by `sable.score.voi.compute_voi` but not yet called by the CLI. Synthetic fixtures are not evidence of live detection accuracy.

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

Until the `analyze` command is added, analyse a snapshot from Python:

```python
import json
from sable.graph.build import analyze
from sable.fix.planner import finalize_results
from sable.score.voi import compute_voi
from sable.report.html import write_report

snapshot = json.load(open("tests/fixtures/snapshots/weak2.json"))
complete = finalize_results(analyze(snapshot, {"extra_entry_points": ["www-data"]}))
complete["voi"] = compute_voi(complete)
write_report(complete, "output/weak2")
```

Run the read-only collector against a host (writes a redacted, schema-valid snapshot):

```sh
# Bring up the Docker lab targets first (ports 2221-2224):
make targets-up

# Collect weak1 over SSH (auditor / auditorpass are lab-only):
SABLE_PW=auditorpass python -m sable.collect auditor@localhost --port 2221 \
  --password-env SABLE_PW --yes --output output/weak1.snapshot.json

# Then analyse the snapshot from Python (see the example below) or validate it:
sable validate snapshot output/weak1.snapshot.json
```

Analyse a snapshot straight to a report, or run a full SSH scan, with the CLI:

```sh
# Snapshot -> analyze -> finalize -> VOI -> report, no SSH:
sable analyze tests/fixtures/snapshots/weak3.json --output output/weak3

# Full scan over SSH (collect -> analyze -> report) in one command:
SABLE_PW=auditorpass sable scan auditor@localhost --port 2221 \
  --password-env SABLE_PW --yes --output output/weak1
```

Generate remediation scripts, or apply chmod/chown fixes on a host you control:

```sh
sable remediate output/weak3/results.json --output output/weak3   # writes fix.sh + rollback.sh
sable remediate output/weak3/results.json --apply --state state.json   # gated apply (chmod/chown only)
sable rollback state.json                                          # restore recorded owner/mode
```

Offline target acceptance runs without Docker:

```sh
make integration   # analyses each target's authored snapshot vs expected.yaml
```

All commands return exit code 0 on success and 2 for handled input/configuration/I/O
errors. `remediate --apply` and `rollback` change files and run `chmod`/`chown`
locally; use them only on a host you are authorised to change.

Install `.[dev,app]` when implementing Paramiko SSH collection and NetworkX analysis.
Jinja2, PyYAML, jsonschema and timestamp validation are already core dependencies.
The SSH defaults in `config/sable.yaml` are reserved for future collection; current
`plan`/`report` commands accept the scoring/planner configuration, not SSH credentials.

## Verification status

Last verified locally on **17 November 2026** (Windows 11, Python 3.13):

- **171 Python tests passed**, covering the KB, graph analysis, scoring, VOI,
  contracts, planning, reporting and the installed CLI (regular installation).
- Result fixtures are regenerated from the snapshots by the analyzer, and a test
  fails if they drift from it.

Previously verified on **14 November 2026** (macOS, Python 3.14), before the analyzer existed:

- 61 Python tests passed.
- The guide's exact-solver example produces greedy size 3 versus exact size 2.
- All four synthetic target reports passed isolated offline browser checks with no
  JavaScript errors or HTTP(S) requests; selecting recommended fixes matched residual predictions.
- Desktop/mobile layouts were inspected, including the graph resize correction.
- The built wheel was checked for packaged schemas, HTML/JS templates, Cytoscape.js
  and its license.

These are local results, not a claim that GitHub CI or live target tests have run.
CI is configured for Python 3.10 and 3.12; the latest local environment used Python 3.14.

Verified offline with `python -m pytest -q` on **both CPython 3.10.22 and 3.12.16:
275 passed, 6 skipped** (the skips are per-target conditional integration checks),
satisfying NF-03's two-version requirement; a GitHub Actions workflow
(`.github/workflows/ci.yml`) runs the same on 3.10 and 3.12.

Verified **live** against the Docker lab (Docker 29.8.2): `sable scan` over real SSH
produced the expected findings on all four targets, NV-02's `docker diff` certificate
passed on hardened with no unexpected changes, and the full remediation cycle on weak2
(generate `fix.sh` → apply → rescan shows the root path gone → `rollback.sh` → rescan
shows it back, stat identical) worked end to end. The collector was also run against
ubuntu 22.04, ubuntu 24.04 and debian:12 base images (NF-03). The AG-07 top-paths SVG
and the CVE fixed-version cross-check (two jammy kernel values corrected) are also
done; the remaining item is the team's human peer review.

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

`make setup` installs `.[dev,app]`; `make test`, `make validate` and `make fixtures`
(regenerate result fixtures after KB/graph changes) use the active Python. On Windows,
use `.venv\Scripts\python` and install `setuptools` in the venv before the
`--no-build-isolation` reinstall. Override `PYTHON` if needed. No formatter or linter is currently configured.

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
- [Analysis](docs/ANALYSIS.md): KB, attack graph, scoring and VOI APIs and acceptance status.
- [Planning and reporting](docs/PLANNING_AND_REPORTING.md): APIs, configuration and acceptance status.
- [Collection](docs/COLLECTION.md): collector architecture, evidence contract and EC/CL/TE/NV-02 acceptance.
- [Remediation](docs/REMEDIATION.md): fix scripts, gated apply/rollback and the end-to-end CLI.
- [Decisions](docs/DECISIONS.md): scope and unresolved integration questions.

Never commit SSH passwords, private keys, API tokens, real sensitive snapshots or
unredacted logs. Generated reports belong under ignored `output/`. Committed fixtures
are synthetic and use reserved `example.test` hostnames. Output redaction supplements,
but does not replace, removing secrets inside the future collector before persistence.
