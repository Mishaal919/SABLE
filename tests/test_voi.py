"""NV-01 value of information (next best check)."""
import copy
import json

import pytest

from analysis_helpers import FIXTURES, account, credential, snapshot, sudo
from sable.contracts.validation import ContractError, dumps, validate
from sable.fix.planner import finalize_results
from sable.graph.build import analyze
from sable.score.voi import compute_voi

MISSING_SUDOERS = [{'check': 'sudoers_full', 'reason': 'permission_denied'}]


def unprivileged():
    return snapshot(credential(), account('dbadmin'), missing=MISSING_SUDOERS)


def elevated():
    return snapshot(credential(), account('dbadmin'), sudo(user='dbadmin', commands=['/usr/bin/find']), mode='elevated')


def with_unrelated_unknown(results):
    """Add an unknown whose edge starts at an account no entry can reach."""
    results = copy.deepcopy(results)
    results['unknowns'].append({'id': 'u-99', 'prior': 0.5, 'resolving_check': 'unrelated_check'})
    results['graph']['nodes'].append({'id': 'user:ghost', 'kind': 'privilege'})
    results['graph']['edges'].append({'id': 'e-99', 'src': 'user:ghost', 'dst': 'root', 'rule': 'unknown_sudo',
                                      'evidence_ids': [results['evidence'][0]['id']], 'attack': 'T1548.003',
                                      'likelihood': 0.27, 'unknown_id': 'u-99',
                                      'breakdown': {'base': 0.9, 'strength': 'unknown', 'factor': 0.3}})
    return results


def test_unreadable_sudoers_check_ranks_first_and_unrelated_unknown_is_zero():
    results = with_unrelated_unknown(analyze(unprivileged()))
    voi = compute_voi(results)
    unknowns = {u['id']: u for u in results['unknowns']}
    assert unknowns[voi[0]['unknown']]['resolving_check'] == 'sudoers_full'
    assert voi[0]['value'] > 0
    assert voi[-1] == {'unknown': 'u-99', 'value': 0.0, 'changes_top_fix': False}


def test_elevated_scan_resolves_the_unknown():
    results = analyze(elevated())
    assert results['unknowns'] == [] and compute_voi(results) == []
    root = [p for p in results['paths'] if p['goal'] == 'root']
    assert root and all(e['breakdown']['strength'] != 'unknown' for e in results['graph']['edges'])


def test_value_formula_and_top_fix_bonus():
    results = json.loads((FIXTURES / 'results/weak3.analysis.json').read_text(encoding='utf-8'))
    results['unknowns'] = [{'id': 'u-01', 'prior': 0.5, 'resolving_check': 'capability_check'}]
    root_edge = results['graph']['edges'][0]
    root_edge.update(unknown_id='u-01', likelihood=0.27, breakdown={'base': 0.9, 'strength': 'unknown', 'factor': 0.3})
    results['paths'][0].update(confidence=0.27, band='Low')
    # Baseline top fix blocks shadow (0.8); if u-01 is true the 0.9 root path takes over.
    voi = compute_voi(results)
    assert voi == [{'unknown': 'u-01', 'value': pytest.approx(0.5 * 0.63 + 0.5 * 0.27 + 0.1), 'changes_top_fix': True}]
    assert compute_voi(results, {'voi_bonus': 0})[0]['value'] == pytest.approx(0.45)


def test_repeated_runs_are_identical_and_inputs_unchanged():
    results = with_unrelated_unknown(analyze(unprivileged()))
    before = dumps(results)
    outputs = {dumps(compute_voi(results)) for _ in range(5)}
    assert len(outputs) == 1 and dumps(results) == before


def test_voi_completes_planned_results():
    complete = finalize_results(analyze(unprivileged()))
    complete['voi'] = compute_voi(complete)
    validate(complete, 'results')
    assert complete['voi'][0]['unknown'] == 'u-01'


@pytest.mark.parametrize('bonus', [-0.1, float('nan'), True])
def test_invalid_bonus_is_rejected(bonus):
    with pytest.raises(ContractError):
        compute_voi(analyze(unprivileged()), {'voi_bonus': bonus})
