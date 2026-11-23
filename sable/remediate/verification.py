"""RM-05: rescan the local Linux host as the original scan account after apply."""
import os
import platform
import shutil
import subprocess
import time
from copy import deepcopy

from sable.collect.allowlist import CommandResult, render
from sable.collect.audit import AuditLog
from sable.collect.errors import CommandTimeout
from sable.remediate.errors import RemediationError


def preflight(results):
    """Fail before applying if the original scan account cannot be used locally."""
    if platform.system() != 'Linux':
        raise RemediationError('Post-apply rescanning requires Linux on the assessed host')
    import pwd
    try:
        account = pwd.getpwnam(results['meta']['user'])
    except KeyError as exc:
        raise RemediationError('Original scan account does not exist on this host') from exc
    if os.geteuid() != account.pw_uid and (os.geteuid() != 0 or not shutil.which('runuser')):
        raise RemediationError('Rescan must run as the original account, or as root with runuser available')
    return account.pw_uid


class LocalReadOnlyRunner:
    """Reuse the fixed read-only registry; parameters are validated by render()."""
    def __init__(self, user, uid, audit_path, timeout=30):
        self.user, self.uid, self.timeout = user, uid, timeout
        self.audit = AuditLog(audit_path)

    def run(self, command_id, **params):
        command = render(command_id, params)
        argv = ['sh', '-c', command]
        if os.geteuid() != self.uid:
            argv = ['runuser', '-u', self.user, '--'] + argv
        started = time.monotonic()
        try:
            completed = subprocess.run(argv, capture_output=True, text=True,
                                       encoding='utf-8', errors='replace', timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            self.audit.record(command_id, command, 'timeout', time.monotonic() - started)
            raise CommandTimeout('Post-apply collection command timed out') from exc
        duration = time.monotonic() - started
        self.audit.record(command_id, command, completed.returncode, duration)
        return CommandResult(command_id, command, completed.stdout, completed.stderr, completed.returncode, duration)


def verification_config(results, config=None):
    """Retain entry points, asset goals and thresholds from the original analysis."""
    config = deepcopy(config or {})
    scan = config.get('scan', {})
    config.setdefault('extra_entry_points', scan.get('extra_entry_points', sorted({
        p['entry'][5:] for p in results['paths'] if p['entry'].startswith('user:')
        and p['entry'] != 'user:' + results['meta']['user']})))
    config.setdefault('asset_goals', scan.get('asset_goals', [
        g['goal'] for g in results['goals'] if g['goal'].startswith('asset:')]))
    for key in ('bands', 'path_cutoff'):
        if key in results.get('planning', {}):
            config.setdefault(key, results['planning'][key])
    return config


def collect_after_apply(results, config, audit_path):
    from sable.collect.collector import run_collection, assemble_snapshot
    uid = preflight(results)
    runner = LocalReadOnlyRunner(results['meta']['user'], uid, audit_path,
                                 config.get('ssh', {}).get('command_timeout_seconds', 30))
    elevated = results['meta']['mode'] == 'elevated'
    meta, evidence, missing = run_collection(runner, {'elevated': elevated})
    return assemble_snapshot(results['meta']['host'], meta, evidence, missing, results['meta']['mode'])


def compare_after_apply(results, state, after, config):
    """Compare to the prediction for fixes actually applied, not declined/manual ones."""
    from sable.fix.paths import residual_risk
    from sable.remediate.apply import residual_matches
    from sable.report.compare import compare_scans
    selected = [fix for fix in results['fixes'] if fix['id'] in state['applied']]
    config = {**config, 'entries': sorted({p['entry'] for p in results['paths']} | {'user:' + results['meta']['user']}),
              'goals': [g['goal'] for g in results['goals']]}
    predicted = residual_risk(results['graph'], results['paths'], selected, config)
    comparison = residual_matches({'residual': predicted}, after)
    diff = compare_scans({**results, 'paths': predicted['paths']}, after)
    comparison.update(diff)
    comparison['paths_match'] = not diff['added'] and not diff['removed']
    comparison['applied_fix_ids'] = list(state['applied'])
    return comparison
