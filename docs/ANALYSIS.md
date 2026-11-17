# Knowledge base, attack graph and scoring (Hamzah)

These modules turn a validated snapshot into `stage: analysis` results: attack
graph, paths, goal confidence, represented unknowns and candidate fixes. They also
compute value of information (NV-01). They never open SSH connections, execute
commands or modify the snapshot.

## Python interfaces

```python
from sable.graph.build import analyze, build_graph
from sable.score.voi import compute_voi
from sable.fix.planner import finalize_results
from sable.kb.loader import load_kb

analysis = analyze(snapshot, config)          # validated, stage "analysis"
complete = finalize_results(analysis, config)  # Thomas's planner + residual
complete["voi"] = compute_voi(complete, config)  # orchestrator fills VOI
```

`analyze(snapshot, config=None, kb=None)` validates the snapshot, loads the packaged
KB unless one is supplied, builds the graph, enumerates paths, scores goals,
instantiates fix candidates through the planner's `build_candidates`, and validates
the output against the source snapshot. `compute_voi(results, config=None)` works on
analysis or complete results and returns the ranked `voi` list. It calls
`plan_fixes`; the planner never calls VOI. Wiring `sable analyze` and VOI into the
CLI is Thomas's orchestration work.

`config` accepts the flat keys of `config/scoring.yaml` (strength_factors, bands,
path_cutoff, unknown_prior, goal_exact_edge_limit, goal_samples, random_seed,
voi_bonus) plus `extra_entry_points` and `asset_goals`, either flat or under the
`scan:` section used by `config/sable.yaml`.

## Module map

| File | Guide IDs | Responsibility |
|---|---|---|
| `sable/kb/data/meta.yaml` | KB-05 | Catalogue version/date copied to `meta.kb_version` / `meta.kb_date` |
| `sable/kb/data/binaries.yaml` | KB-01 | 42 GTFOBins entries with suid/sudo/capability contexts |
| `sable/kb/data/cves.yaml` | KB-02 | 18 local privilege-escalation CVEs with per-distro fixed versions and CVSS |
| `sable/kb/data/rules.yaml` | KB-03, NV-05, RE-05 | 15 rules: match conditions, edge, base likelihood, fix + rollback templates, ATT&CK ID, optional CIS |
| `sable/kb/kb.schema.json`, `loader.py` | KB-04 | Loads every `*.yaml` in the folder, validates, reports file and field on error |
| `sable/kb/versions.py` | KB-02 | dpkg version comparison (epochs, revisions, `~`), no extra dependency |
| `sable/graph/build.py` | AG-01..03, AG-05, AG-06 | Rule engine, entry points, goals, pruning, stable IDs, `analyze()` |
| `sable/graph/paths.py` | AG-04, CS-02, CS-06 | Simple-path enumeration over edge IDs, path confidence, bands |
| `sable/score/likelihood.py` | CS-01, CS-04, CS-05 | base x strength factor with breakdown; CVSS base; config factors |
| `sable/score/goal.py` | CS-03 | Shared-edge-aware goal confidence (exact, else seeded Monte Carlo) |
| `sable/score/voi.py` | NV-01 | Value of information per unknown |

`sable/fix/paths.py` now re-exports `band`, `enumerate_paths` and `goal_scores` from
these modules and keeps only `residual_risk`, so there is a single definition of
confidence for analysis, planning, residuals and VOI.

The guide suggests `networkx.all_simple_paths`. That walks node pairs and merges
parallel edges from different rules; the shared implementation walks edge IDs so
each rule/evidence step stays distinct, and output order is fixed. NetworkX is
therefore not needed; the graph stays in the contract's JSON form.

## How the graph is built

1. **Entries (AG-02):** `user:<scan user>` plus `extra_entry_points`.
2. **Rules (KB-03):** `kind: match` rules are pure data. Each inspects one evidence
   type, checks `when` conditions (eq, ne, in, glob, not_glob, any_contains),
   optionally requires the binary to be in `binaries.yaml` with a context, and adds
   one edge per actor (`entries` or users named in an evidence field) to the target.
   `user:root` normalises to `root`; edges out of root are skipped.
3. **Built-in kinds** read their base/ATT&CK/fix from `rules.yaml`:
   - `cve`: package version in a catalogued vulnerable range for `meta.distro`.
     Kernel CVEs use the package `linux-image-<meta.kernel>` (the running kernel).
     Base = CVSS/10, strength at most `inferred` (version-only match).
   - `credential_reuse`: readable stored password -> each interactive account
     (uid >= 1000, login shell, not the scan user). Strength at most `inferred`;
     it is labelled as a possibility, never as proven reuse.
   - `unknown_sudo`: when the `sudoers_full` check is in `missing`, each
     interactive non-scan account without recorded sudo rules gets an
     `unknown`-strength edge to root with an `unknown_id`. The unknown's
     `resolving_check` is `sudoers_full` (elevated mode). A missing check alone
     creates nothing: a user-account evidence record is required.
4. **Evidence (AG-05):** every edge cites the evidence that created it; an edge with
   no or unresolved evidence raises `ContractError`.
5. **Pruning:** only nodes reachable from the entries are kept, plus root,
   configured goals and possible-entry services. The weak2 cron path therefore
   appears only when www-data is an entry.
6. **Goals (AG-03):** root always, plus every reachable asset/credential node, plus
   `asset_goals` (plain paths become `asset:<path>`).
7. **Possible entries (AG-06):** running services with a non-loopback listener
   become `service:<name>` nodes with `possible_entry: true` and no edges.
8. **IDs (NF-05):** edges `e-NN` in evidence order, then rule/src/dst; paths `p-NN`
   by descending confidence; fixes `f-NN` by their first broken edge; unknowns
   `u-NN`. Same snapshot + KB + config gives byte-identical output.

## Scoring

- Step likelihood = base x strength factor (observed 1.0, inferred 0.6, unknown
  0.3 by default). The edge stores `breakdown` {base, strength, factor}, so every
  path score can be recomputed from its edges (CS-04).
- A multi-evidence step uses the weakest supporting strength.
- Path confidence = product of step likelihoods (independence assumption).
- Goal confidence counts each edge once (0.48 example), exact up to 16 edges.
- Bands: High >= 0.6, Medium >= 0.3, from `bands` in config.

## Value of information (NV-01)

For each unknown u with prior p: set u's edges to observed (true) or remove them
(false), re-enumerate paths, re-score goals and rerun `plan_fixes`.
`VOI = p*|goal change if true| + (1-p)*|goal change if false| + bonus`, where the
goal change sums absolute changes over all goals and `voi_bonus` (default 0.1) is
added when either scenario changes the top greedy fix. The list is sorted by value
then unknown ID. An unknown that touches no path scores 0.

## Fixtures

`python tests/fixtures/regenerate.py` (or `make fixtures`) rebuilds every
`results/*.analysis.json`, completed `results/*.json` (planner + VOI) and
`terminal_weak3.txt` from the committed snapshots. weak2 is generated with
`extra_entry_points: [www-data]`. `test_committed_analysis_fixtures_match_the_analyzer`
fails when KB/graph changes are not followed by regeneration.

## Developer guide acceptance status

| Requirement | Verification |
|---|---|
| KB-01 | Catalogue schema-validated on load; SUID find creates a step, SUID passwd does not |
| KB-02 | 20 table-driven dpkg comparisons; vulnerable polkit gives CVSS 0.78 x inferred 0.6; fixed version, other distro and non-running kernel do not match |
| KB-03 | Positive and negative fixture for every rule; test fails if a rule has no case |
| KB-04 | Drop-in rule file used without code change; malformed files name file and field |
| KB-05 | kb_version/kb_date copied to results and shown in the report footer |
| AG-01 | weak1 graph has exactly the expected nodes and edge |
| AG-02 | weak2 path only with www-data entry (flat or `scan:` config) |
| AG-03 | weak3 reaches root and asset:/etc/shadow; root always a goal; configured goals added |
| AG-04 | Parallel-edge count, cutoff and cycle tests |
| AG-05 | Builder refuses missing/unknown evidence; trace check over all fixtures |
| AG-06 | apache on 0.0.0.0:80 marked possible entry, loopback mysql not, no path uses it |
| CS-01 | Base (rule default, CVSS) x every strength table |
| CS-02 | 0.9 x 0.8 x 0.5 = 0.36 |
| CS-03 | Shared edge 0.48 (exact and seeded Monte Carlo) |
| CS-04 | Breakdown recomputes every stored path score for all fixtures |
| CS-05 | Changing the inferred factor in config changes the score |
| CS-06 | Thresholds from config at and just below each boundary |
| NV-01 | Unreadable sudoers ranks first; elevated scan removes the unknown; unrelated unknown 0; formula and bonus; repeatable |
| NV-05 | Every rule has an ATT&CK ID from the accepted list; every generated edge carries one |
| NF-02 | Path -> edge -> evidence -> source_cmd trace over all fixtures |
| NF-05 | Five analyze runs byte-identical per target |
| AG-07 | Not implemented (Should). The report's Cytoscape graph covers visualisation; an SVG export would add graphviz/matplotlib |

## Known limits

- CVE fixed versions were compiled from USN/DSA advisories without network access
  during development. Cross-check them against the Ubuntu and Debian trackers
  before evaluation. Some CVEs need extra preconditions (noted per entry) that the
  version match cannot confirm, which is why they are `inferred`.
- `writable_by` / `readable_by` are treated as user names. Group-based access must be
  expanded to users by the collector or a future rule extension.
- SGID-only binaries, cap_dac_read_search and non-root scheduled jobs do not create
  edges yet.
- The scan user's own sudo rules are unknown only if the collector records them as
  missing. No rule models that case yet.

## Architecture and security-analysis notes

The analyzer is a pure function of snapshot, catalogue and configuration. Rules are
data, so detection logic can be reviewed and extended without code changes, and
every edge is traceable to evidence records and a rule ID with an ATT&CK tag.
Uncertainty is explicit: version matches and credential reuse are `inferred`, and
facts hidden by permissions become `unknown` edges tied to the check that would
resolve them. These lower scores instead of being dropped or asserted, and VOI
ranks which read-only check would most change the conclusions. Confidence uses one
shared definition across analysis, planning and residual risk. Goal scoring avoids
double counting shared steps, and fixed ordering and seeds keep results
reproducible for comparison between scans.
