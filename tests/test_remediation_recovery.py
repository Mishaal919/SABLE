"""Recovery must survive refusal, partial failure and untrusted display text."""
import json
import os
import subprocess
from copy import deepcopy

import pytest

from sable.remediate import apply_fixes, generate_scripts, parse_operations, rollback_from_state, LocalRunner
from sable.remediate.errors import RemediationError, UnsafeFix
from sable.remediate.verification import compare_after_apply, verification_config
from test_remediate import FakeRunner, _results

# Tests that exercise real POSIX semantics (chmod/chown modes, os.geteuid, runuser,
# a working bash) run on Linux/CI; they are skipped on non-POSIX hosts.
posix_only = pytest.mark.skipif(os.name != 'posix', reason='requires POSIX chmod/account/bash semantics')


@pytest.mark.parametrize('command', [
    'chmod 640 /tmp/*', 'chmod 640 /tmp/[ab]', 'chmod 640 /tmp/a &&',
    '&& chmod 640 /tmp/a', 'chmod 640 /tmp/a\nwhoami',
    'chmod 640 /tmp/../etc/shadow', 'chmod 640 /', 'chmod 640 /tmp/$(whoami)',
])
def test_unsafe_commands_refused(command):
    with pytest.raises(UnsafeFix):
        parse_operations(command)


@posix_only
def test_script_comments_and_shared_paths(tmp_path):
    results = _results('weak3.json')
    fix = next(f for f in results['fixes'] if f['execution'] == 'script_and_apply')
    fix['description'] = 'Review\ntouch /tmp/not-executable'
    fix['command'] = "chmod 640 '/tmp/file with spaces'"
    results['fixes'].append({**fix, 'id': 'f-extra'})
    results['fixes'][0]['command'] = 'manual\ntouch /tmp/not-executable'
    scripts = generate_scripts(results)
    assert scripts['fix.sh'].count("record '/tmp/file with spaces'") == 1
    assert all(line.startswith('# ') for line in scripts['fix.sh'].splitlines() if 'touch ' in line)
    for name in ('fix.sh', 'rollback.sh'):
        path = tmp_path / name
        path.write_text(scripts[name])
        subprocess.run(['bash', '-n', str(path)], check=True)


def test_existing_state_refused_before_writes(tmp_path):
    runner = FakeRunner({'/etc/shadow': ('644', 'root', 'shadow')})
    state = tmp_path / 'state.json'
    state.write_text('previous recovery data')
    with pytest.raises(RemediationError):
        apply_fixes(_results('weak3.json'), runner, lambda _: True, state)
    assert runner.ops == []
    assert state.read_text() == 'previous recovery data'


def test_declined_fixes_cannot_be_rolled_back():
    runner = FakeRunner({})
    state = apply_fixes(_results('weak3.json'), runner)
    assert state['originals'] == []
    assert rollback_from_state(state, runner) == []


@posix_only
def test_partial_failure_preserves_recovery(tmp_path):
    runner = FakeRunner({'/etc/shadow': ('644', 'root', 'shadow')})
    original_chmod = runner.chmod
    def fail_after_change(mode, path):
        original_chmod(mode, path)
        raise RemediationError('simulated failure')
    runner.chmod = fail_after_change
    path = tmp_path / 'state.json'
    with pytest.raises(RemediationError):
        apply_fixes(_results('weak3.json'), runner, lambda _: True, path)
    state = json.loads(path.read_text())
    assert state['status'] == 'failed' and state['started'] and not state['applied']
    runner.chmod = original_chmod
    rollback_from_state(state, runner)
    assert runner.files['/etc/shadow'] == ('644', 'root', 'shadow')
    assert path.stat().st_mode & 0o777 == 0o600


@posix_only
def test_real_file_apply_and_rollback(tmp_path):
    path = tmp_path / 'owned file'
    path.write_text('temporary acceptance fixture')
    path.chmod(0o644)
    before = path.stat()
    fix = {'id': 'f-test', 'type': 'chmod', 'execution': 'script_and_apply',
           'description': 'Restrict temporary file', 'command': f"chmod 600 '{path}'"}
    state = apply_fixes({'fixes': [fix]}, LocalRunner(), lambda _: True, tmp_path / 'state.json')
    assert path.stat().st_mode & 0o777 == 0o600
    rollback_from_state(state, LocalRunner())
    after = path.stat()
    assert (after.st_mode, after.st_uid, after.st_gid) == (before.st_mode, before.st_uid, before.st_gid)
    assert path.read_text() == 'temporary acceptance fixture'


def test_malformed_recovery_validated_before_mutation():
    runner = FakeRunner({})
    records = [{'path': '/tmp/a', 'mode': '644', 'owner': '0', 'group': '0'},
               {'path': '/tmp/b', 'mode': '999', 'owner': '0', 'group': '0'}]
    with pytest.raises(RemediationError):
        rollback_from_state({'originals': records}, runner)
    assert runner.ops == []


def test_rescan_prediction_excludes_manual_and_declined_fixes():
    before = _results('weak3.json')
    comparison = compare_after_apply(before, {'applied': []}, before, verification_config(before))
    assert comparison['paths_match'] and comparison['match']
    after = deepcopy(before)
    after['graph']['edges'][0]['rule'] = 'different-rule'
    comparison = compare_after_apply(before, {'applied': []}, after, verification_config(before))
    assert comparison['match'] and not comparison['paths_match']


@posix_only
def test_local_rescan_uses_original_account_and_allowlist(tmp_path, monkeypatch):
    import sable.remediate.verification as verification
    from sable.collect.errors import CommandNotAllowed, CommandTimeout
    calls = []
    monkeypatch.setattr(verification.os, 'geteuid', lambda: 0)
    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, 'identity', '')
    monkeypatch.setattr(verification.subprocess, 'run', run)
    runner = verification.LocalReadOnlyRunner('auditor', 1000, tmp_path / 'audit.log')
    assert runner.run('system_identity').stdout == 'identity'
    assert calls[0][:4] == ['runuser', '-u', 'auditor', '--']
    with pytest.raises(CommandNotAllowed):
        runner.run('not-a-command')
    assert len(calls) == 1
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('test', 1)
    monkeypatch.setattr(verification.subprocess, 'run', timeout)
    with pytest.raises(CommandTimeout):
        runner.run('system_identity')
    assert 'exit=timeout' in (tmp_path / 'audit.log').read_text()
