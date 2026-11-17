import copy
import json
from pathlib import Path

import pytest
from sable.contracts.validation import ContractError, dumps, validate
from sable.fix.paths import goal_scores, enumerate_paths
from sable.fix.planner import build_candidates, finalize_results, plan_fixes

FIXTURES = Path(__file__).parent / 'fixtures/results'


def load(name):
    return json.loads((FIXTURES / f'{name}.analysis.json').read_text(encoding='utf-8'))


def candidate(fid, edges):
    return {'id': fid, 'breaks_edges': edges, 'type': 'chmod', 'description': fid,
            'command': 'chmod 640 /example', 'rollback': 'Restore recorded mode', 'execution': 'script_and_apply'}


def edge(eid, src, dst, likelihood=.8):
    return {'id': eid, 'src': src, 'dst': dst, 'rule': 'example', 'evidence_ids': ['ev-01'],
            'likelihood': likelihood, 'breakdown': {'base': likelihood, 'factor': 1., 'strength': 'observed'}}


def six_paths():
    edges = [edge(str(i), 'user:a', f'asset:{i}') for i in range(1, 7)]
    graph = {'nodes': [{'id': n, 'kind': 'privilege'} for n in ['user:a'] + [f'asset:{i}' for i in range(1,7)]], 'edges': edges}
    paths = [{'id': str(i), 'entry': 'user:a', 'goal': f'asset:{i}', 'edges': [str(i)], 'confidence': .8, 'band': 'High'} for i in range(1,7)]
    fixes = [candidate('A', ['1','2','3']), candidate('B', ['4','5','6']), candidate('C', ['1','2','4','5'])]
    return graph, paths, fixes


def test_exact_guide_counterexample_and_risk_curve():
    graph, paths, fixes = six_paths()
    plan = plan_fixes(graph, paths, {'fix_candidates': fixes})
    assert plan['fix_sets']['greedy'] == ['C', 'A', 'B']
    assert plan['fix_sets']['exact'] == ['A', 'B']
    assert [f['risk_removed'] for f in plan['fixes']] == pytest.approx([3.2, .8, .8])
    curve = plan['planning']['risk_curve']
    assert [p['percent'] for p in curve] == sorted(p['percent'] for p in curve)
    assert curve[-1]['percent'] == pytest.approx(100)
    for _ in range(5):
        assert dumps(plan_fixes(graph, list(reversed(paths)), {'fix_candidates': list(reversed(fixes))})) == dumps(plan)


@pytest.mark.parametrize('target', ['weak1', 'weak2', 'weak3', 'hardened'])
def test_finalize_all_fixtures_without_mutation(target):
    original = load(target)
    saved = copy.deepcopy(original)
    result = finalize_results(original)
    assert original == saved
    validate(result, 'results')
    assert result['stage'] == 'complete'
    assert result['residual']['paths'] == []
    assert not any(g['confidence'] for g in result['residual']['goals'])


def test_unfixable_path_remains_and_exact_is_honest():
    original = load('weak3')
    original['fix_candidates'] = original['fix_candidates'][1:]
    result = finalize_results(original)
    assert result['planning']['exact_status'] == 'uncoverable'
    assert result['fix_sets']['exact'] is None
    assert result['residual']['paths'][0]['goal'] == 'root'
    assert result['residual']['paths'][0]['confidence'] == .9


def test_exact_skips_more_than_fifteen_candidates():
    graph, paths, _ = six_paths()
    result = plan_fixes(graph, paths, {'fix_candidates': [candidate(str(i), ['1']) for i in range(16)]})
    assert result['fix_sets']['exact'] is None
    assert result['planning']['exact_status'] == 'skipped_limit'


def test_robust_adds_unknown_low_path_and_preserves_expected_set():
    original = load('weak3')
    original['unknowns'] = [{'id':'u-01', 'prior':.5, 'resolving_check':'capability_check'}]
    e = original['graph']['edges'][0]
    e.update(unknown_id='u-01', likelihood=.1, breakdown={'base':1., 'factor':.1, 'strength':'unknown'})
    original['paths'][0].update(confidence=.1, band='Low')
    result = finalize_results(original)
    assert result['fix_sets']['greedy'] == ['f-02']
    assert result['fix_sets']['robust'] == ['f-02', 'f-01']
    assert len(result['residual']['paths']) == 1
    assert result['residual']['paths'][0]['band'] == 'Low'


def test_shared_edge_goal_confidence():
    graph = {'nodes': [], 'edges': [edge('a','start','mid',.5), edge('b','mid','root',.8), edge('c','mid','root',.8)]}
    paths = [{'goal':'root','edges':['a','b']}, {'goal':'root','edges':['a','c']}]
    assert goal_scores(graph, paths, ['root'], {})[0]['confidence'] == pytest.approx(.48)
    assert goal_scores(graph, paths, ['root'], {'goal_exact_edge_limit':0}) == goal_scores(graph, paths, ['root'], {'goal_exact_edge_limit':0})


def test_cycle_and_cutoff():
    graph = {'nodes': [], 'edges': [edge('a','start','mid'), edge('b','mid','start'), edge('c','mid','root')]}
    assert len(enumerate_paths(graph, ['start'], ['root'], {})) == 1
    assert enumerate_paths(graph, ['start'], ['root'], {'path_cutoff':1}) == []


def test_template_mapping_merges_edges_and_requires_rollback():
    original = load('weak1')
    graph = copy.deepcopy(original['graph'])
    graph['edges'].append({**graph['edges'][0], 'id':'e-02'})
    template = {'readable_credential': {'type':'chmod','description':'Protect {path}', 'command':'chmod 640 {path}', 'rollback':'Restore recorded permissions for {path}'}}
    fixes = build_candidates(graph, original['evidence'], template)
    assert len(fixes) == 1
    assert fixes[0]['breaks_edges'] == ['e-01','e-02']
    assert fixes[0]['command'] == 'chmod 640 /var/www/config.php'
    del template['readable_credential']['rollback']
    with pytest.raises(ContractError):
        build_candidates(graph, original['evidence'], template)


def test_rejects_missing_rollback_and_unsafe_automation():
    graph, paths, fixes = six_paths()
    fixes[0]['rollback'] = ''
    with pytest.raises(ContractError):
        plan_fixes(graph, paths, {'fix_candidates':fixes})
    fixes[0]['rollback'] = 'Restore'
    fixes[0]['type'] = 'sudo'
    with pytest.raises(ContractError):
        plan_fixes(graph, paths, {'fix_candidates':fixes})


@pytest.mark.parametrize('value,expected', [(.6,'High'),(.5999,'Medium'),(.3,'Medium'),(.2999,'Low')])
def test_threshold_boundaries(value,expected):
    from sable.fix.paths import band
    assert band(value,{}) == expected


def test_rejects_invalid_thresholds_and_disconnected_path():
    graph, paths, fixes = six_paths()
    with pytest.raises(ContractError):
        plan_fixes(graph, paths, {'fix_candidates':fixes,'bands':{'medium_min':.9,'high_min':.6}})
    paths[0]['edges'] = ['nonexistent']
    with pytest.raises(ContractError):
        plan_fixes(graph, paths, {'fix_candidates':fixes})


def test_finalize_builds_kb_templates_when_provided():
    original = load('weak1')
    original['fix_candidates'] = []
    result = finalize_results(original, {'fix_templates': {'readable_credential': {
        'type':'chmod', 'description':'Restrict {path}', 'command':'chmod 640 {path}', 'rollback':'Restore recorded mode for {path}'}}})
    assert result['fixes'][0]['command'] == 'chmod 640 /var/www/config.php'
    assert result['residual']['paths'] == []
