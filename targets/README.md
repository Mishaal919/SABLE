# Lab targets (Mishaal)

Four targets from developer-guide section 4, each with a `Dockerfile`, an authored
`snapshot.json` and an `expected.yaml`.

| Target | SSH port | Planted weakness | SABLE must report |
|---|---|---|---|
| weak1 | 2221 | Readable `config.php` DB password reused by `dbadmin`, who has `NOPASSWD: /usr/bin/find` | `auditor -> cred -> dbadmin -> root` (Low, sudo unknown) + readable credential; fixes: `chmod 640`, sudo recommendation |
| weak2 | 2222 | Root cron runs `/opt/backup.sh`, group-writable by `www-data` | `www-data -> root` (High), only with `www-data` enabled as entry; fix: `chown root:root && chmod 755` |
| weak3 | 2223 | `cap_setuid+ep` on a python copy + world-readable `/etc/shadow` | `auditor -> root` and `auditor -> asset:/etc/shadow` (High); fixes: remove capability, `chmod 640` |
| hardened | 2224 | None | Zero paths to root, no High-confidence paths |
| compat-ubuntu2404 | 2225 | World-readable `/etc/shadow` (ubuntu 24.04) | NF-03: collector works on ubuntu 24.04 |
| compat-debian12 | 2226 | World-readable `/etc/shadow` (debian 12) | NF-03: collector works on debian 12 |

## Running the lab (TE-04)

```sh
make targets-up       # build + start all four (needs Docker)
make targets-reset    # recreate from scratch
make targets-down     # stop and remove
```

Scan account: `auditor` / `auditorpass` (lab only). The passwords planted in the
weak targets are synthetic lab-only values, never real secrets.

## Offline use

`snapshot.json` in each target is an authored stand-in representing the read-only
collector's output for that host. The integration harness
(`tests/integration/test_targets.py`) runs these through the analyzer and planner and
checks them against `expected.yaml` with **no Docker and no SSH**. When the live lab
is brought up, replace each stand-in with a freshly collected, validated snapshot and
confirm the analyzer output is unchanged.

## weak1 note (team coordination)

weak1 is modelled faithfully, including `dbadmin`'s account, so the analyzer emits
the credential-reuse and unknown-sudo chain. Thomas's
`test_path_explanations_use_recorded_evidence` asserts "no dbadmin" against the
**synthetic** `tests/fixtures/snapshots/weak1.json`, which is left untouched, so it is
unaffected. When the real weak1 snapshot becomes the canonical fixture, revisit that
assertion with the team (see PROGRESS.md / docs/DECISIONS.md item 1).
