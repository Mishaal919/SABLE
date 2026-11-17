"""EC-13: assemble evidence from the checks into a validated, redacted snapshot.

:func:`run_collection` takes a :class:`~sable.collect.allowlist.CommandRunner` (real
or fake) and returns ``(meta, evidence, missing)`` — it is pure with respect to the
runner, so the whole pipeline is unit-tested with canned command output and no SSH.
:func:`collect_snapshot` is the live entry point: authorise, connect, run, assemble.

Determinism (NF-05): evidence is sorted by type then canonical data before IDs are
assigned, so the same host state always yields the same snapshot (ignoring the meta
timestamp).
"""
import json
from datetime import datetime, timezone

from sable.collect.allowlist import CommandRunner
from sable.collect.audit import AuditLog
from sable.collect.authorize import confirm_authorisation
from sable.collect.certificate import not_run
from sable.collect.checks._util import group_members
from sable.collect.checks.accounts import parse_accounts, parse_ssh_settings
from sable.collect.checks.capabilities import parse_capabilities
from sable.collect.checks.credentials import credential_evidence, scan_text
from sable.collect.checks.identity import parse_identity
from sable.collect.checks.packages import parse_packages
from sable.collect.checks.permissions import parse_permissions, parse_world_writable
from sable.collect.checks.scheduled import assemble_scheduled, parse_cron
from sable.collect.checks.services import parse_services
from sable.collect.checks.suid import parse_suid
from sable.collect.checks.sudo import parse_sudo_list, parse_sudoers
from sable.collect.checks._util import parse_stat_lines
from sable.collect.errors import CommandTimeout, NotAuthorised
from sable.contracts.validation import validate
from sable.redaction import redact

_MAX_CRED_FILES = 200


def _sable_version():
    try:
        from importlib.metadata import version
        return version('sable')
    except Exception:
        return '0.1.0'


def _timestamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _safe(runner, missing, check, command_id, **params):
    """Run a command, recording a missing check on timeout. Returns stdout or None."""
    try:
        return runner.run(command_id, **params).stdout
    except CommandTimeout:
        missing.append({'check': check, 'reason': 'timeout'})
        return None


def run_collection(runner, config=None):
    """Collect evidence and missing checks using ``runner``. Returns (meta, evidence, missing)."""
    config = config or {}
    elevated = bool(config.get('elevated'))
    missing = []
    evidence = []

    identity_out = runner.run('system_identity').stdout
    meta = parse_identity(identity_out)
    scan_user = meta['user']

    passwd = _safe(runner, missing, 'user_accounts', 'user_accounts')
    group_text = _safe(runner, missing, 'groups', 'groups') or ''
    accounts = parse_accounts(passwd, group_text) if passwd else []
    members = group_members(accounts)
    evidence += accounts

    effective = _safe(runner, missing, 'ssh_settings', 'ssh_effective_config')
    if effective is not None:
        config_text = '' if effective.strip() else (_safe(runner, missing, 'ssh_settings', 'ssh_config_file') or '')
        evidence += parse_ssh_settings(effective, config_text)

    suid_out = _safe(runner, missing, 'suid_find', 'suid_find')
    if suid_out is not None:
        evidence += parse_suid(suid_out)

    perms_out = _safe(runner, missing, 'sensitive_permissions', 'sensitive_permissions')
    if perms_out is not None:
        evidence += parse_permissions(perms_out, accounts, members)
    ww_out = _safe(runner, missing, 'sensitive_permissions', 'world_writable')
    if ww_out is not None:
        evidence += parse_world_writable(ww_out, accounts, members)

    caps_out = _safe(runner, missing, 'file_capabilities', 'file_capabilities')
    if caps_out is not None:
        evidence += parse_capabilities(caps_out)

    pkg_out = _safe(runner, missing, 'installed_packages', 'installed_packages')
    if pkg_out is not None:
        evidence += parse_packages(pkg_out)

    svc_sections = _safe(runner, missing, 'services', 'services')
    if svc_sections is not None:
        ss_part, _, systemd_part = svc_sections.partition('##SABLE##')
        evidence += parse_services(ss_part, systemd_part)

    cron_out = _safe(runner, missing, 'scheduled_jobs', 'scheduled_jobs')
    if cron_out is not None:
        jobs = parse_cron(cron_out, scan_user)
        script_paths = sorted({job['script_path'] for job in jobs})
        stat_rows = []
        if script_paths:
            stat_out = _safe(runner, missing, 'scheduled_jobs', 'stat_paths', paths=script_paths)
            if stat_out:
                stat_rows = parse_stat_lines(stat_out)
        evidence += assemble_scheduled(jobs, stat_rows, accounts, members)

    evidence += _collect_credentials(runner, missing, accounts, members)

    sudo_result = _run_sudo(runner, missing, scan_user, elevated)
    evidence += sudo_result

    return meta, evidence, missing


def _collect_credentials(runner, missing, accounts, members):
    from sable.collect.checks._util import accessors
    find_out = _safe(runner, missing, 'credential_scan', 'credential_find')
    if find_out is None:
        return []
    account_names = [a['data']['name'] for a in accounts]
    files = [line.strip() for line in find_out.splitlines() if line.strip().startswith('/')][:_MAX_CRED_FILES]
    stat_map = {}
    if files:
        stat_out = _safe(runner, missing, 'credential_scan', 'stat_paths', paths=files)
        if stat_out:
            stat_map = {path: (mode, owner, group) for mode, owner, group, path in parse_stat_lines(stat_out)}
    evidence = []
    for path in files:
        text = _safe(runner, missing, 'credential_scan', 'read_file', path=path)
        if not text:
            continue
        matches = scan_text(text)
        del text  # drop file contents immediately; never stored
        if not matches:
            continue
        if path in stat_map:
            mode, owner, group = stat_map[path]
            readable_by, _ = accessors(mode, owner, group, account_names, members)
        else:
            readable_by = ['root']
        evidence += credential_evidence(path, matches, readable_by)
    return evidence


def _run_sudo(runner, missing, scan_user, elevated):
    try:
        result = runner.run('sudo_rules')
    except CommandTimeout:
        missing.append({'check': 'sudoers', 'reason': 'timeout'})
        return []
    own_rules, _password_required = parse_sudo_list(result.stdout, result.exit_status, scan_user)
    evidence = list(own_rules)
    if elevated:
        full = _safe(runner, missing, 'sudoers_full', 'sudoers_full')
        if full:
            evidence += parse_sudoers(full)
    else:
        # Unprivileged scans cannot read other accounts' sudo rights (EC-15); record
        # the gap so the analyzer can model an unknown escalation for interactive users.
        missing.append({'check': 'sudoers_full', 'reason': 'permission_denied'})
    return evidence


def _order_evidence(evidence):
    """Sort evidence deterministically and assign ev-NN IDs."""
    ordered = sorted(evidence, key=lambda item: (item['type'], item['source_cmd'],
                                                  json.dumps(item['data'], sort_keys=True)))
    width = max(2, len(str(len(ordered))))
    for index, item in enumerate(ordered, start=1):
        item['id'] = f'ev-{index:0{width}d}'
    return ordered


def assemble_snapshot(host, meta_fields, evidence, missing, mode, no_writes=None,
                      secrets=(), timestamp=None, sable_version=None):
    """Build, redact and validate a snapshot from collected parts."""
    meta = {
        'host': host,
        'distro': meta_fields['distro'],
        'kernel': meta_fields['kernel'],
        'user': meta_fields['user'],
        'groups': sorted(dict.fromkeys(meta_fields.get('groups', []))) or [meta_fields['user']],
        'mode': mode,
        'timestamp': timestamp or _timestamp(),
        'sable_version': sable_version or _sable_version(),
    }
    if meta_fields.get('architecture'):
        meta['architecture'] = meta_fields['architecture']
    ordered_missing = sorted({(m['check'], m['reason'], m.get('detail') or '') for m in missing})
    missing_list = [{'check': c, 'reason': r, **({'detail': d} if d else {})} for c, r, d in ordered_missing]
    snapshot = {
        'schema_version': '1.0',
        'meta': meta,
        'evidence': _order_evidence(evidence),
        'missing': missing_list,
        'no_writes': no_writes or not_run(),
    }
    snapshot = redact(snapshot, secrets)
    validate(snapshot, 'snapshot')
    return snapshot


def collect_snapshot(host, user, *, port=22, key_path=None, password=None,
                     accept_new_host_key=False, timeout=30, config=None,
                     audit_path=None, assume_yes=False, secrets=(), prompt=input):
    """Live collection: authorise, connect over SSH, run checks, return a snapshot."""
    from sable.collect import ssh
    config = config or {}
    if not confirm_authorisation(assume_yes, prompt):
        raise NotAuthorised('authorisation declined; no connection was opened')
    client = ssh.connect(host, user, port=port, key_path=key_path, password=password,
                         accept_new_host_key=accept_new_host_key, timeout=timeout)
    try:
        audit = AuditLog(audit_path, secrets) if audit_path else AuditLog('audit.log', secrets)
        runner = CommandRunner(client, audit, timeout=timeout)
        meta_fields, evidence, missing = run_collection(runner, config)
        mode = 'elevated' if config.get('elevated') else 'unprivileged'
        return assemble_snapshot(host, meta_fields, evidence, missing, mode, secrets=secrets)
    finally:
        ssh.close(client)
