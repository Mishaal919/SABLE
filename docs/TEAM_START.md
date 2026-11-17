# Starting work in parallel

Read CONTRACTS.md first. Validate every producer's output before handing it off.

| Owner | Start now | Handoff / dependency |
|---|---|---|
| Mishaal | collect/, allow-list, redaction before persistence, SSH safety, targets | snapshot schema; real target fixtures and audit/certificate output |
| Hamzah | kb/, graph/, score/ against synthetic snapshots | analysis results, candidate templates, pure path/scoring functions |
| Thomas | fix/, report/, CLI orchestration against analysis fixtures | pure greedy planner early for VOI; complete results for reporting |
| Shared | redaction helper, schema changes, integration cases | producer + consumer review for every contract change |

Module names follow the guide. Fix planning and HTML/terminal reporting are
implemented (PLANNING_AND_REPORTING.md), as are the KB, attack-graph generation,
scoring and VOI (ANALYSIS.md). Collection, Docker targets, the analyze/scan CLI
commands and target integration tests are still to be implemented. Do not run fixture `command` strings as an execution API.

First integration milestone: collect one lab snapshot -> validate -> analyse ->
validate analysis -> plan and compute residual -> populate VOI -> validate complete
results against snapshot -> render self-contained HTML. Then test all four targets.

Feature done: automated acceptance checks, schema and fixture for new data, another
member's review, and a short architecture/security-analysis paragraph, per the guide.
