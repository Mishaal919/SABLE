# Remediation and end-to-end CLI (Thomas)

Covers `sable/remediate/` and the `analyze`/`scan`/`remediate`/`rollback` CLI
commands. Remediation is a **separate, explicitly gated boundary** from collection: it
never runs commands over the read-only scan channel, and it never executes a command
string from a results file.

## How a fix becomes an action

A completed result's `fixes` carry a display `command` (e.g. `chmod 640 /etc/shadow`)
and an `execution` tag the planner set: `script_and_apply` for chmod/chown, else
`recommend_only`. Remediation:

1. `operations.parse_operations(command)` re-derives the intended operation and
   **validates every argument** (mode `^[0-7]{3,4}$`, owner spec, absolute safe path).
   Anything that is not a well-formed chmod/chown — sudo, service, capability, manual,
   or an injection attempt — raises `UnsafeFix`. This is the real refusal mechanism.
2. `scripts.generate_scripts` writes `fix.sh` (records original owner/mode to a state
   file before each change, then applies chmod/chown) and `rollback.sh` (restores every
   recorded path). recommend-only fixes appear only as commented recommendations.
3. `apply.apply_fixes` records original state to `state.json` **first**, confirms each
   change, then runs parsed operations through a runner (`LocalRunner` = argument-list
   subprocess, no shell). `rollback.rollback` restores from `state.json`.

## Pipeline

`analyze <snapshot>` and `scan user@host` run: (collect →) `analyze` →
`finalize_results` → `compute_voi` → `write_report`. VOI is now populated by the CLI,
so reports made this way carry the next-best-check ranking.

## Acceptance matrix

| ID | Feature | How it is verified | Status |
|---|---|---|---|
| RP-05 | Reversible fixes + rollback | templates required (planner); apply records state, rollback restores | ✅ logic/tests · ⬜ real stat-identical on a target (Docker) |
| RM-01 | fix.sh / rollback.sh | `test_remediate.py::test_generate_scripts_weak3` | ✅ |
| RM-02 | Gated apply (chmod/chown only) | `test_apply_*` (fake runner, state.json, confirm) | ✅ unit · ⬜ real apply (Docker) |
| RM-03 | Rollback command | `test_rollback_restores_original_state`, CLI `rollback` | ✅ unit · ⬜ real rollback (Docker) |
| RM-04 | Never automate sudo/service | `test_parse_refuses_non_chmod_chown`, recommend-only stays commented | ✅ |
| RM-05 | Re-scan after fixes | `residual_matches` + `test_residual_matches` | ✅ compare · ⬜ live rescan (Docker) |
| CL-01 | Stage commands | `test_cli_commands.py` (analyze/scan/remediate/rollback) + installed-CLI test | ✅ |
| CL-02 | Flags + config | existing + scan/analyze `--config`/flags | ✅ |
| NF-03 | Compatibility 3.10/3.12 | suite run on 3.10.22 and 3.12.16; CI matrix | ✅ · ⬜ scan each base image (Docker) |

## Safety notes

- Only chmod/chown are applyable; capability stays recommend-only (DECISIONS item 5).
- `apply`/`rollback` run `chmod`/`chown` locally — use only on a host you control.
  A remote apply runner would implement the same `stat/chmod/chown` interface with a
  write allow-list, kept entirely separate from the read-only collector.
- `state.json` and `audit.log` are git-ignored; never commit them.
