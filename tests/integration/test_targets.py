"""TE-01/TE-02/TE-03: offline target acceptance.

Runs each lab target's authored snapshot through the real analyzer and planner and
checks it against the target's ``expected.yaml``. No Docker and no SSH: this proves
detection against the planted chains using the collector's output contract. A live
variant (scanning the running containers) is added when ``make targets-up`` is used.
"""
import json
import pathlib

import pytest
import yaml

from sable.contracts.validation import validate
from sable.fix.planner import finalize_results
from sable.graph.build import analyze
from sable.kb.loader import load_kb

TARGETS_DIR = pathlib.Path(__file__).resolve().parents[2] / 'targets'
NAMES = ['weak1', 'weak2', 'weak3', 'hardened']
BANDS = {'Low': 0, 'Medium': 1, 'High': 2}


def load_target(name):
    base = TARGETS_DIR / name
    snapshot = json.loads((base / 'snapshot.json').read_text(encoding='utf-8'))
    expected = yaml.safe_load((base / 'expected.yaml').read_text(encoding='utf-8'))
    return snapshot, expected


def config_for(expected):
    return {
        'extra_entry_points': list(expected.get('extra_entry_points') or []),
        'asset_goals': list(expected.get('asset_goals') or []),
    }


def best_band(paths, entry, goal):
    matches = [p for p in paths if p['entry'] == entry and p['goal'] == goal]
    if not matches:
        return None
    return max(matches, key=lambda p: p['confidence'])['band']


@pytest.fixture(params=NAMES)
def target(request):
    name = request.param
    snapshot, expected = load_target(name)
    results = analyze(snapshot, config_for(expected))
    return name, snapshot, expected, results


def test_snapshot_is_valid(target):
    _name, snapshot, _expected, _results = target
    validate(snapshot, 'snapshot')


def test_expected_paths_present_with_band(target):
    name, _snapshot, expected, results = target
    for path in expected.get('expected_paths') or []:
        band = best_band(results['paths'], path['entry'], path['goal'])
        assert band is not None, f'{name}: missing path {path["entry"]} -> {path["goal"]}'
        assert band == path['band'], (
            f'{name}: {path["entry"]} -> {path["goal"]} band {band}, expected {path["band"]}')


def test_no_unexpected_high_paths(target):
    """Precision: every High path must be one the target expects (recall + no extras)."""
    name, _snapshot, expected, results = target
    allowed = {(p['entry'], p['goal']) for p in (expected.get('expected_paths') or []) if p['band'] == 'High'}
    high = {(p['entry'], p['goal']) for p in results['paths'] if p['band'] == 'High'}
    assert high <= allowed, f'{name}: unexpected High paths {sorted(high - allowed)}'


def test_forbidden_paths(target):
    name, _snapshot, expected, results = target
    if expected.get('forbid_root_paths'):
        root_paths = [p for p in results['paths'] if p['goal'] == 'root']
        assert not root_paths, f'{name}: expected zero paths to root, found {len(root_paths)}'
    if expected.get('forbid_high_paths'):
        high = [p for p in results['paths'] if p['band'] == 'High']
        assert not high, f'{name}: expected no High paths, found {len(high)}'


def test_expected_fixes_present(target):
    name, _snapshot, expected, results = target
    candidates = results['fix_candidates']
    for want in expected.get('expected_fixes') or []:
        matching = [c for c in candidates if c['type'] == want['type']]
        assert matching, f'{name}: no candidate fix of type {want["type"]}'
        if 'matches' in want:
            assert any(want['matches'] in c.get('command', '') for c in matching), (
                f'{name}: no {want["type"]} fix touching {want["matches"]}')


def test_requires_entry_point(target):
    """weak2: the escalation must vanish when the required service entry is removed (AG-02)."""
    name, snapshot, expected, _results = target
    required = expected.get('requires_entry_point')
    if not required:
        pytest.skip('no entry-point requirement for this target')
    without = analyze(snapshot, {'extra_entry_points': [], 'asset_goals': config_for(expected)['asset_goals']})
    assert not without['paths'], f'{name}: path found without the {required} entry point'


def test_unknown_resolving_check(target):
    name, _snapshot, expected, results = target
    check = expected.get('expect_unknown_resolving_check')
    if not check:
        pytest.skip('no unknown expected for this target')
    checks = {u['resolving_check'] for u in results['unknowns']}
    assert check in checks, f'{name}: expected an unknown resolved by {check}, got {sorted(checks)}'


def test_complete_results_validate(target):
    """The planner produces schema-valid complete results preserving the snapshot."""
    _name, snapshot, expected, results = target
    complete = finalize_results(results, config_for(expected))
    validate(complete, 'results', snapshot=snapshot)
    assert complete['stage'] == 'complete'
    assert complete['residual'] is not None


def test_breaking_a_rule_breaks_detection():
    """TE-03 meta-check: if a KB rule is removed, the planted path disappears.

    Proves the acceptance test is real (it would fail on a broken catalogue). The
    committed KB is not modified; the rule is dropped from an in-memory copy only.
    """
    snapshot, expected = load_target('weak2')
    baseline = analyze(snapshot, config_for(expected))
    assert any(p['goal'] == 'root' for p in baseline['paths'])

    kb = load_kb()
    kb['rules'] = {rid: rule for rid, rule in kb['rules'].items() if rid != 'writable_root_cron'}
    broken = analyze(snapshot, config_for(expected), kb=kb)
    assert not any(p['goal'] == 'root' for p in broken['paths']), (
        'removing writable_root_cron should remove weak2 root path')
