# Fix planning and reports

These modules accept an already generated attack graph. They do not connect over
SSH, generate graph edges, execute fixes, or calculate value of information.

## Run locally

```sh
python -m pip install '.[dev]'
sable report tests/fixtures/results/weak3.analysis.json --output output/demo
sable plan tests/fixtures/results/weak1.analysis.json --output output/planned.json
sable report output/planned.json --output output/weak1
sable compare output/weak1/results.json output/demo/results.json
python -m pytest -q
```

`report` produces report.html, results.json, and summary.txt, and prints the summary.
An analysis-stage input is first completed by the planner. A complete input is
rendered unchanged unless configuration overrides request replanning. `plan` always
replans and writes one results JSON file. Exit 0 means success; 2 means invalid
input/configuration or a read/write error. These are offline commands; they do not
pretend to implement the future scan, remediate or rollback commands.

Use `--config config/scoring.yaml` for YAML settings. `--path-cutoff 4` overrides
the file. Supply known secrets with repeated `--redact-env ENVIRONMENT_VARIABLE_NAME`;
the CLI reads their values without putting the values in shell arguments or output.

## Python interfaces

```python
from sable.fix.planner import build_candidates, plan_fixes, finalize_results
from sable.report.html import write_report
from sable.report.terminal import terminal_summary

# Pure planning entry point for Hamzah's NV-01 scenario analysis:
plan = plan_fixes(graph, paths, {"fix_candidates": candidates})
# plan contains fixes, fix_sets and planning diagnostics; no graph is modified.

complete = finalize_results(analysis_results, {"path_cutoff": 6})
files = write_report(complete, "output/run", secrets=[session_password])
print(terminal_summary(complete, secrets=[session_password]))
```

The input graph is the JSON mapping defined in results.schema.json, not a NetworkX
instance. A NetworkX producer should export nodes/edges into that format first.
Paths must be connected simple paths with correct products of edge likelihoods.
The low-level planner validates graph/path structure and candidates; the full
finalizer additionally validates evidence links and the results contract.

`finalize_results` enumerates paths in the supplied graph, retaining IDs for unchanged
paths, then calls the planner and recomputes residual paths and goals after edge
removal. It never constructs attack edges or tries to infer additional weaknesses.
It preserves the supplied VOI list; Hamzah remains responsible for computing VOI.

Explicit `entries` and `goals` lists can be supplied in config. Otherwise entries
come from supplied paths plus the scan account; goals come from supplied goal
records plus root when that node exists. Thus a new service entry with no supplied
path must be passed explicitly. Path cutoff is 6 by default.

Goal confidence enumerates independent edge states for up to 16 edges, counting a
shared edge once. Larger cases use 10,000 Monte Carlo samples with seed 0. Configure
`goal_exact_edge_limit` (0–20), `goal_samples`, and `random_seed` if needed. This
adapter exists so residual reporting works before Hamzah's scorer is available;
it can later be replaced by his scorer while preserving the interface and tests.

## KB template handoff (RP-01/RP-05)

Pass `fix_templates` in finalizer config to instantiate candidate fixes instead of
using the existing `fix_candidates`. Or call `build_candidates` directly. The mapping
is keyed by rule ID, and each value contains type, description, command, rollback:

```yaml
fix_templates:
  readable_credential:
    type: chmod
    description: "Restrict access to {path}"
    command: "chmod 640 {path}"
    rollback: "Restore the recorded mode and owner of {path}"
```

Only simple named placeholders are accepted. They resolve against each supporting
evidence record's data, plus src, dst and rule. Missing values or rollback templates
fail rather than inventing information. Rules needing data joined across several
evidence records should supply already instantiated fix_candidates. Identical rendered
fixes merge their broken edges. Missing rule templates leave paths unfixable and
visible as residual risk. No strings are executed by these modules.

## Planning semantics

- Greedy covers High and Medium paths, maximizing remaining summed confidence;
  ties use fix ID. Marginal reductions determine display order. Low paths remain.
- Exact checks every combination by size, up to 15 candidates, to block all High
  paths. Its report comparison uses a separate High-only greedy run. More than 15
  candidates yields skipped_limit; an impossible cover yields uncoverable, not a
  misleading empty optimal set.
- Robust sets preserve the expected set, set represented unknown edges to likelihood
  1, enumerate worst-case paths and add fixes greedily. This is a conservative
  superset, not a claim of an optimal worst-case solution.
- The risk curve measures cumulative reduction in breakable High/Medium path risk.
  With no such risk, the report says so instead of claiming 100% remediation.
- Residual results are predictions assuming every selected recommendation is applied,
  including recommend-only fixes. No server modification is implied.

## Report guarantees and integration boundaries

The HTML adds short evidence-based path explanations, affected-path counts for
fixes, and contextual goal/residual descriptions through report/explanations.py.
Application disclaimers appear only in the final Limitations section; other sections
retain factual statuses and may link there. Empty reports do not announce fixes.
Unknown mechanisms are described only through supplied graph facts.

The HTML uses autoescaped Jinja2, inline CSS, inline SVG and vendored Cytoscape.js
3.30.4 (MIT; license in sable/report/vendor). A restrictive CSP disables network
access. JSON embedded in scripts uses Jinja2's HTML-safe tojson; graph labels and
what-if rows use text, never interpolated HTML. All original graph paths remain
in the embedded data and checking a fix blocks any path containing one of its edges.

Outputs use the shared redact() helper before serialization. It handles supplied
literal secrets, common labelled password/token values, bearer tokens, private keys,
and credentials in URLs. It is not a guarantee against arbitrary unlabelled secrets:
Mishaal's collector must still remove secrets at source and use the same helper for
future snapshots/logs. The planner does not persist input data itself.

The schema now permits optional planning diagnostics, edge cis tags, and kb_date.
Existing baseline fixtures still validate. No schema_version change was needed for
these optional producer fields; producer/consumer documentation changed together.

## Developer guide acceptance status

| Requirement | Implementation / verification |
|---|---|
| RP-01 | KB template mapping and shared-edge deduplication tests |
| RP-02 | Pure API, deterministic selection and shuffled-input repeatability |
| RP-03 | Guide's A/B/C example gives greedy 3, exact 2; displayed gap tested |
| RP-04 | Edge removal, new path enumeration and goal scoring; all four synthetic cases |
| RP-05 | Rollback required by candidate/schema/template validation; real apply/rollback stat test remains a remediation/target integration task |
| RP-06 | Marginal ordering and risk curve checks |
| RE-01/02 | Single offline HTML, required headings, desktop/mobile browser inspection |
| RE-03 | Schema validation and stable JSON round-trip |
| RE-04 | Top paths, top three fixes, mode and terminal snapshot test |
| RE-05 | Optional CIS display test |
| RE-06 | Shared helper and seeded-secret tests across HTML, JSON and terminal files; future collector/log writers must integrate it |
| RE-07 | Structural path comparison, removed paths and confidence-change tests |
| NV-03 | Offline select/clear check; recommended selection equals residual prediction |
| NV-04 | Unknown-edge superset test and monotone curve reaching all breakable risk |

Browser checks are optional developer tooling: install Playwright for Node, then run
`node tests/browser/check-report.cjs` after generating output/demo. Set
BROWSER_EXECUTABLE to a local Chrome binary if Playwright browsers are not installed.
The browser test uses an isolated offline context and saves desktop/mobile screenshots.
The Python CI suite runs on 3.10 and 3.12; this does not claim CI has already run.

## Architecture and security-analysis notes

The planner is a deterministic function of graph, paths, candidates and settings,
so the CLI, report generator and VOI analysis share one implementation without
SSH or UI dependencies. Candidate mapping, coverage selection and residual
recalculation are separate operations. The reporter consumes completed results,
which retain the evidence and original scan metadata necessary for auditability.

The planner's risk sum is a prioritisation heuristic rather than compromise
probability; overlapping paths can contribute more than 1. Goal probabilities
handle shared edges separately. Exact comparisons demonstrate greedy's limits.
Unknown-edge scenarios expose uncertainty without asserting unsupported edges.
Reports preserve missing checks and never convert an unperformed filesystem audit
into a passing no-writes certificate. Escaping, offline resource bundling and
pre-serialization redaction protect report consumers, while real detection and
rollback accuracy still require integration with the lab targets.
