"""RM-01..RM-05: remediation script generation, gated apply and rollback."""
import json
import pathlib

import pytest

from sable.remediate import (
    apply_fixes,
    generate_scripts,
    is_applyable,
    parse_operations,
    paths_of,
    residual_matches,
    rollback_from_state,
)
from sable.remediate.errors import UnsafeFix

FIXTURES = pathlib.Path(__file__).resolve().parent / 'fixtures' / 'results'


def _results(name):
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


class FakeRunner:
    """In-memory filesystem: {path: (mode, owner, group)}."""

    def __init__(self, files):
        self.files = dict(files)
        self.ops = []

    def stat(self, path):
        if path not in self.files:
            raise AssertionError(f'stat on unknown path {path}')
        return self.files[path]

    def chmod(self, mode, path):
        self.ops.append(('chmod', mode, path))
        _m, owner, group = self.files.get(path, ('000', 'root', 'root'))
        self.files[path] = (mode, owner, group)

    def chown(self, spec, path):
        self.ops.append(('chown', spec, path))
        mode, _o, _g = self.files.get(path, ('000', 'root', 'root'))
        owner, _, group = spec.partition(':')
        self.files[path] = (mode, owner, group or owner)


# --- operations parsing (RM-04 refusal) ------------------------------------
def test_parse_chmod_and_chown():
    ops = parse_operations('chown root:root /opt/backup.sh && chmod 755 /opt/backup.sh')
    assert [(o.verb, o.argument, o.path) for o in ops] == [
        ('chown', 'root:root', '/opt/backup.sh'), ('chmod', '755', '/opt/backup.sh')]


def test_parse_refuses_non_chmod_chown():
    with pytest.raises(UnsafeFix):
        parse_operations('visudo: remove NOPASSWD from the rule for dbadmin')
    with pytest.raises(UnsafeFix):
        parse_operations('setcap -r /opt/python')


def test_parse_rejects_injection_and_bad_args():
    with pytest.raises(UnsafeFix):
        parse_operations('chmod 640 /etc/shadow; rm -rf /')
    with pytest.raises(UnsafeFix):
        parse_operations('chmod 99999 /etc/shadow')
    with pytest.raises(UnsafeFix):
        parse_operations('chmod 640 relative/path')


# --- RM-01 script generation -----------------------------------------------
def test_generate_scripts_weak3():
    results = _results('weak3.json')
    scripts = generate_scripts(results)
    fix_sh = scripts['fix.sh']
    assert fix_sh.startswith('#!/usr/bin/env bash')
    assert 'set -euo pipefail' in fix_sh
    assert 'record ' in fix_sh and '/etc/shadow' in fix_sh
    assert 'chmod 640 /etc/shadow' in fix_sh
    # Capability fix is recommend-only: present only as a manual recommendation.
    assert 'Manual recommendations' in fix_sh
    assert 'setcap -r /opt/python' in fix_sh
    assert scripts['applied'] >= 1
    rb = scripts['rollback.sh']
    assert 'chmod "$mode" "$path"' in rb and 'chown "$owner:$group" "$path"' in rb


def test_generated_fix_does_not_script_recommend_only():
    results = _results('weak3.json')
    fix_sh = generate_scripts(results)['fix.sh']
    # The capability fix is recommend-only; every setcap line must be commented out.
    setcap_lines = [line for line in fix_sh.splitlines() if 'setcap' in line]
    assert setcap_lines and all(line.lstrip().startswith('#') for line in setcap_lines)


# --- RM-02 gated apply ------------------------------------------------------
def test_apply_records_state_applies_and_skips(tmp_path):
    results = _results('weak3.json')
    runner = FakeRunner({'/etc/shadow': ('644', 'root', 'shadow')})
    state_path = tmp_path / 'state.json'
    state = apply_fixes(results, runner, confirm=lambda prompt: True, state_path=str(state_path))

    assert any(o == ('chmod', '640', '/etc/shadow') for o in runner.ops)
    assert runner.files['/etc/shadow'][0] == '640'
    assert state['originals'][0] == {'path': '/etc/shadow', 'mode': '644', 'owner': 'root',
                                     'group': 'shadow', 'fix_id': state['applied'][0]}
    # recommend-only fixes are skipped, never applied
    assert state['skipped']
    saved = json.loads(state_path.read_text(encoding='utf-8'))
    assert saved['originals'] == state['originals']


def test_apply_confirm_no_skips_change():
    results = _results('weak3.json')
    runner = FakeRunner({'/etc/shadow': ('644', 'root', 'shadow')})
    state = apply_fixes(results, runner, confirm=lambda prompt: False)
    assert not any(op[0] == 'chmod' and op[2] == '/etc/shadow' for op in runner.ops)
    assert state['applied'] == []


# --- RM-03 rollback ---------------------------------------------------------
def test_rollback_restores_original_state():
    results = _results('weak3.json')
    runner = FakeRunner({'/etc/shadow': ('644', 'root', 'shadow')})
    state = apply_fixes(results, runner, confirm=lambda prompt: True)
    assert runner.files['/etc/shadow'][0] == '640'
    restored = rollback_from_state(state, runner)
    assert '/etc/shadow' in restored
    assert runner.files['/etc/shadow'] == ('644', 'root', 'shadow')


# --- RM-05 rescan comparison ------------------------------------------------
def test_residual_matches():
    results = _results('weak3.json')
    # A rescan with the same number of paths as the predicted residual matches.
    predicted = len(results['residual']['paths'])
    assert residual_matches(results, {'paths': [None] * predicted})['match'] is True
    assert residual_matches(results, {'paths': [None] * (predicted + 1)})['match'] is False


def test_write_scripts_uses_lf_newlines(tmp_path):
    from sable.remediate import write_scripts
    written = write_scripts(_results('weak3.json'), tmp_path)
    for path in written.values():
        raw = path.read_bytes()
        assert b'\r\n' not in raw, 'shell scripts must use LF (CRLF breaks bash)'
        assert raw.startswith(b'#!/usr/bin/env bash')


def test_is_applyable_and_paths_of():
    chmod_fix = {'type': 'chmod', 'execution': 'script_and_apply', 'command': 'chmod 640 /etc/shadow'}
    sudo_fix = {'type': 'sudo', 'execution': 'recommend_only', 'command': 'visudo: ...'}
    assert is_applyable(chmod_fix) and not is_applyable(sudo_fix)
    assert paths_of(chmod_fix) == ['/etc/shadow']
