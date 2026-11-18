# Collection, safety and test targets (Mishaal)

This document covers the read-only collector (`sable/collect/`), the four Docker lab
targets (`targets/`) and the offline integration harness (`tests/integration/`). It
is the owner's reference and the architecture/security paragraph the guide requires.

## Architecture

```
user@host ─ ssh.connect() ─▶ one SSH client (host-key verified, timeouts)
                               │
                 CommandRunner.run(id)  ── the ONLY exec_command caller (EC-02)
                               │  audits every command (CL-03)
        allow-listed read-only commands (allowlist.ALLOWLIST)
                               │
         checks/*.py  pure parsers ── command text ▶ typed evidence
                               │
         collector.run_collection() ─▶ evidence + missing + meta
                               │  redact at source (EC-10) + shared redact()
         collector.assemble_snapshot() ─▶ validate(snapshot) ─▶ snapshot.json
```

Design rules:

- **One gateway.** Only `CommandRunner.run` calls `exec_command`; a CI test
  (`test_exec_command_only_appears_in_allowlist_module`) fails if that leaks.
- **Fixed templates.** Commands are frozen strings; variable parts are named
  placeholders validated against a strict character set and shell-quoted, so no
  caller input can change a command or chain a second one.
- **Pure parsers.** `checks/*.py` turn command output into evidence with no SSH, so
  the whole pipeline is unit-tested with hand-made strings and an injectable runner.
- **Redaction at the source.** The credential scan records path, line and pattern
  type only — never the secret — and the assembled snapshot is passed through the
  shared `redact()` again before it is written or validated.
- **Determinism (NF-05).** Evidence is sorted by type then canonical data before IDs
  are assigned; the same host state yields the same snapshot (ignoring the meta
  timestamp).

## Public API

```python
from sable.collect import collect_snapshot, run_collection, assemble_snapshot, CommandRunner
from sable.collect.certificate import certificate_from_docker_diff, not_run
```

- `collect_snapshot(host, user, ...) -> snapshot` — live: authorise, connect, run.
- `run_collection(runner, config) -> (meta, evidence, missing)` — pure, runner-driven.
- `assemble_snapshot(host, meta, evidence, missing, mode, ...) -> validated snapshot`.
- `python -m sable.collect user@host --output snapshot.json` — standalone CLI.

The product `sable scan` / `sable analyze --snapshot` subcommands (which also analyse,
plan and report) are wired in `sable/cli.py` by Thomas; they call `collect_snapshot`
here, then `analyze` → `finalize_results` → `compute_voi` → `write_report`.

## Evidence contract produced

Evidence types and their canonical `source_cmd` tags, all matching
`schemas/snapshot.schema.json` and the rules in `sable/kb/data/rules.yaml`:

| Check | Evidence type | source_cmd | Feature |
|---|---|---|---|
| identity | (meta only) | system_identity | EC-03 |
| accounts | user_account | user_accounts | EC-11 |
| ssh settings | ssh_setting | ssh_settings | EC-11 |
| suid/sgid | suid_binary | suid_find | EC-04 |
| sensitive perms / world-writable | file_permission | sensitive_permissions | EC-05 |
| capabilities | capability | file_capabilities | EC-09 |
| packages | package | installed_packages | EC-12 |
| services | service | services | EC-08 |
| scheduled jobs | scheduled_job | scheduled_jobs | EC-07 |
| credentials | credential_location | credential_scan | EC-10 |
| sudo | sudo_rule | sudo_rules / sudoers_full | EC-06 / EC-15 |

`writable_by`/`readable_by` are expanded from owner/group/other bits into concrete
account names (service accounts included) so the analyzer can match an actor against
them. Unprivileged scans record a `sudoers_full` missing check so the analyzer can
model an unknown escalation for interactive accounts (the weak1 chain).

## Acceptance matrix

| Feature | How it is verified | Status |
|---|---|---|
| EC-01 SSH connection | `test_collect_ssh.py`: policy, auth error, unknown/bad host key, network failure (mocked paramiko) | offline ✅; live scan ⏳ Docker |
| EC-02 Allow-list | `test_collect_allowlist.py`: unknown ID rejected, unsafe arg rejected, exec_command single-site CI check | ✅ |
| EC-03 Identity | `test_collect_checks.py::test_parse_identity` | ✅ |
| EC-04 SUID/SGID | `test_parse_suid` | ✅ (count-vs-root ⏳ Docker) |
| EC-05 Permissions | `test_parse_permissions_*`, `test_accessors_*` | ✅ |
| EC-06 Sudo rules | `test_parse_sudo_list*` | ✅ |
| EC-07 Scheduled jobs | `test_parse_cron_and_assemble` + weak2 target | ✅ |
| EC-08 Services | `test_parse_services` | ✅ (version string ⏳ Docker) |
| EC-09 Capabilities | `test_parse_capabilities_both_formats` + weak3 | ✅ |
| EC-10 Credentials + redaction | `test_scan_text_never_returns_secret_values`, collector secret grep | ✅ |
| EC-11 Accounts + ssh | `test_parse_accounts_*`, `test_parse_ssh_settings_*` | ✅ (world-readable key ⏳ Docker) |
| EC-12 Packages | `test_parse_packages` | ✅ |
| EC-13 JSON snapshot | `test_collect_collector.py`: valid snapshot, drives analyzer; live==snapshot ⏳ Docker | offline ✅ |
| EC-14 Source/strength tags | schema-required; `test_source_cmds_are_canonical` | ✅ |
| EC-15 Unprivileged/elevated | `test_unprivileged_scan_records_sudoers_missing`; elevated reads sudoers | ✅ |
| EC-16 Timeouts/denied | `test_timeout_records_missing_and_continues` | ✅ |
| CL-03 Audit log | `test_run_executes_once_and_audits`, `test_every_audit_line_matches_an_allowlist_entry` | ✅ |
| CL-04 Authorisation | `test_collect_safety.py`: declined → no connection | ✅ |
| CL-05 Never store credentials | source redaction + `test_secret_value_never_appears_in_snapshot` | ✅ |
| TE-01 Weak targets | `targets/weak{1,2,3}` + `tests/integration/test_targets.py` | offline ✅; build ⏳ Docker |
| TE-02 Hardened target | `targets/hardened` + harness (zero root/High) | offline ✅; build ⏳ Docker |
| TE-03 Integration harness | `test_targets.py` incl. break-a-rule meta-check | offline ✅ |
| TE-04 One-command up/reset | `docker-compose.yml`, `make targets-up/reset` | authored ⏳ Docker |
| NV-02 No-writes certificate | `test_collect_certificate.py`: pass, flagged write, hashes | logic ✅; live diff ⏳ Docker |
| NF-01 Non-destructive | guaranteed by EC-02, shown by NV-02 | ✅ (logic) |
| NF-03 Compatibility | Python 3.10+ code; run suite on 3.10/3.12 | ⏳ CI |

**⏳ Docker / CI** items were **verified live on 18 November 2026** (Docker 29.8.2):
`make targets-up` ran all four targets; `sable scan` over SSH produced the expected
findings on each (weak1 config.php + dbadmin→root chain + VOI; weak2 www-data→root;
weak3 root + /etc/shadow; hardened zero paths); NV-02's `docker diff` of hardened
passed with no unexpected changes; the suite runs on Python 3.10 and 3.12. The live
run also fixed three collector bugs (dpkg brace escaping, `stat -c` vs `--printf`,
credential over-scoping), now guarded by tests. Remaining: 24.04/debian:12 base
images for NF-03 breadth.

## Running

```sh
python -m pytest -q tests/test_collect_*.py tests/integration   # offline
make targets-up                                                 # build the lab (Docker)
python -m sable.collect auditor@localhost --port 2221 --password-env SABLE_PW --yes
```

## Open items / coordination

- weak1 is modelled faithfully with `dbadmin`; the synthetic fixture and Thomas's
  "no dbadmin" test are untouched (see targets/README.md, DECISIONS.md item 1).
- Live byte-identical live-vs-snapshot (EC-13), SUID/service count comparisons,
  real NV-02 `docker diff` and NF-03 multi-version runs need the Docker lab up.
- `sable scan` / `sable analyze --snapshot` CLI wiring is Thomas's (cli.py).
