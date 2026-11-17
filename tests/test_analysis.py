"""AG-01..AG-06, CS-01..CS-06, NF-02 and NF-05 for the evidence-to-graph analyzer."""
import json

import pytest

from analysis_helpers import FIXTURES, account, capability, credential, fixture_snapshot, package, perm, service, snapshot, strength, suid
from sable.contracts.validation import ContractError, dumps, validate
from sable.graph.build import GraphBuilder, analyze, build_graph
from sable.graph.paths import band, enumerate_paths
from sable.score.goal import goal_scores
from sable.score.likelihood import cvss_base, step_likelihood

TARGET_CONFIG = {'weak1': {}, 'weak2': {'extra_entry_points': ['www-data']}, 'weak3': {}, 'hardened': {}}


def edge(eid, src, dst, likelihood):
    return {'id': eid, 'src': src, 'dst': dst, 'rule': 'r', 'evidence_ids': ['ev-01'], 'likelihood': likelihood,
            'breakdown': {'base': likelihood, 'strength': 'observed', 'factor': 1.0}}


# AG-01 / AG-02 / AG-03 -------------------------------------------------------

def test_weak1_graph_has_expected_nodes_and_edges_only():
    graph = analyze(fixture_snapshot('weak1'))['graph']
    assert graph['nodes'] == [{'id': 'cred:/var/www/config.php', 'kind': 'credential'},
                              {'id': 'root', 'kind': 'privilege'}, {'id': 'user:auditor', 'kind': 'privilege'}]
    assert [(e['src'], e['dst'], e['rule'], e['evidence_ids']) for e in graph['edges']] == [
        ('user:auditor', 'cred:/var/www/config.php', 'readable_credential', ['ev-01'])]


def test_weak2_cron_path_only_with_www_data_entry():
    snap = fixture_snapshot('weak2')
    assert analyze(snap)['paths'] == []
    paths = analyze(snap, {'extra_entry_points': ['www-data']})['paths']
    assert [(p['entry'], p['goal']) for p in paths] == [('user:www-data', 'root')]
    nested = analyze(snap, {'scan': {'extra_entry_points': ['www-data']}})['paths']
    assert nested == paths


def test_weak3_reaches_root_and_shadow_asset_goal():
    results = analyze(fixture_snapshot('weak3'))
    assert {p['goal'] for p in results['paths']} == {'root', 'asset:/etc/shadow'}
    assert {g['goal']: g['confidence'] for g in results['goals']} == {'root': 0.9, 'asset:/etc/shadow': 0.8}


def test_root_is_always_a_goal_and_configured_assets_are_added():
    results = analyze(fixture_snapshot('hardened'), {'asset_goals': ['/root/.ssh/id_rsa']})
    assert results['paths'] == []
    assert results['goals'] == [{'goal': 'asset:/root/.ssh/id_rsa', 'confidence': 0.0}, {'goal': 'root', 'confidence': 0.0}]


def test_hardened_has_no_paths_and_no_high_findings():
    results = analyze(fixture_snapshot('hardened'))
    assert results['paths'] == [] and results['graph']['edges'] == []


def test_multi_step_chain_through_credential_and_account():
    snap = snapshot(credential(), account('dbadmin'), missing=[{'check': 'sudoers_full', 'reason': 'permission_denied'}])
    results = analyze(snap)
    root = [p for p in results['paths'] if p['goal'] == 'root']
    assert len(root) == 1
    rules = [next(e['rule'] for e in results['graph']['edges'] if e['id'] == eid) for eid in root[0]['edges']]
    assert rules == ['readable_credential', 'credential_reuse', 'unknown_sudo']
    assert root[0]['band'] == 'Low'


# AG-04 -----------------------------------------------------------------------

def test_path_count_with_parallel_edges_and_cutoff():
    graph = {'nodes': [], 'edges': [edge('a1', 'u', 'm', .9), edge('a2', 'u', 'm', .8), edge('b1', 'm', 'root', .9),
                                    edge('b2', 'm', 'root', .7), edge('c', 'u', 'root', .5)]}
    assert len(enumerate_paths(graph, ['u'], ['root'], {})) == 5
    assert len(enumerate_paths(graph, ['u'], ['root'], {'path_cutoff': 1})) == 1


def test_paths_are_numbered_in_a_fixed_order():
    results = analyze(snapshot(suid('/usr/bin/find'), perm('/etc/shadow', readable_by=['auditor']), capability('/usr/bin/perl')))
    assert [p['id'] for p in results['paths']] == ['p-01', 'p-02', 'p-03']
    confidences = [p['confidence'] for p in results['paths']]
    assert confidences == sorted(confidences, reverse=True)


# AG-05 / NF-02 ---------------------------------------------------------------

def test_edge_creation_requires_resolvable_evidence():
    builder = GraphBuilder(snapshot(suid('/usr/bin/find'))['evidence'], {})
    with pytest.raises(ContractError, match='no evidence'):
        builder.add_edge('user:a', 'root', 'r', [], .9, 'observed', 'T1068')
    with pytest.raises(ContractError, match='not in the snapshot'):
        builder.add_edge('user:a', 'root', 'r', ['ev-99'], .9, 'observed', 'T1068')


@pytest.mark.parametrize('target', sorted(TARGET_CONFIG))
def test_trace_chain_has_no_broken_links(target):
    for suffix in ('.analysis', ''):
        results = json.loads((FIXTURES / f'results/{target}{suffix}.json').read_text(encoding='utf-8'))
        edges = {e['id']: e for e in results['graph']['edges']}
        evidence = {e['id']: e for e in results['evidence']}
        for path in results['paths'] + ((results['residual'] or {}).get('paths', [])):
            assert all(eid in edges for eid in path['edges'])
        for item in edges.values():
            assert item['evidence_ids'] and all(eid in evidence for eid in item['evidence_ids'])
        assert all(record['source_cmd'] for record in evidence.values())


# AG-06 -----------------------------------------------------------------------

def test_listening_services_are_possible_entries_without_edges():
    results = analyze(snapshot(service('apache2'), service('mysql', address='127.0.0.1', port=3306), credential()))
    nodes = {n['id']: n for n in results['graph']['nodes']}
    assert nodes['service:apache2'].get('possible_entry') is True
    assert 'service:mysql' not in nodes
    assert not any('service:apache2' in (e['src'], e['dst']) for e in results['graph']['edges'])
    assert all(p['entry'] != 'service:apache2' for p in results['paths'])


# CS-01 / CS-04 / CS-05 -------------------------------------------------------

@pytest.mark.parametrize('base', [0.9, cvss_base(7.8), cvss_base(10.0)])
@pytest.mark.parametrize('strength_name,factor', [('observed', 1.0), ('inferred', 0.6), ('unknown', 0.3)])
def test_step_likelihood_table(base, strength_name, factor):
    likelihood, breakdown = step_likelihood(base, strength_name)
    assert breakdown == {'base': base, 'strength': strength_name, 'factor': factor}
    assert likelihood == pytest.approx(base * factor)


def test_evidence_strength_flows_into_edges():
    results = analyze(snapshot(strength(suid('/usr/bin/find'), 'inferred')))
    assert results['graph']['edges'][0]['breakdown'] == {'base': 0.9, 'strength': 'inferred', 'factor': 0.6}


def test_changing_a_factor_in_config_changes_scores():
    snap = snapshot(package('sudo', '1.9.9-1ubuntu2.1'))
    default = analyze(snap)['graph']['edges'][0]['likelihood']
    tuned = analyze(snap, {'strength_factors': {'inferred': 0.5}})['graph']['edges'][0]['likelihood']
    assert default == pytest.approx(0.468) and tuned == pytest.approx(0.39)


@pytest.mark.parametrize('bad', [{'strength_factors': {'observed': 1.5}}, {'strength_factors': {'guess': 0.1}},
                                 {'extra_entry_points': 'www-data'}, {'unknown_prior': 2}])
def test_invalid_analysis_config_is_rejected(bad):
    with pytest.raises(ContractError):
        analyze(fixture_snapshot('weak3'), bad)


@pytest.mark.parametrize('target', sorted(TARGET_CONFIG))
def test_breakdowns_reproduce_every_stored_score(target):
    results = analyze(fixture_snapshot(target), TARGET_CONFIG[target])
    edges = {e['id']: e for e in results['graph']['edges']}
    for item in edges.values():
        assert item['likelihood'] == pytest.approx(item['breakdown']['base'] * item['breakdown']['factor'])
    for path in results['paths']:
        product = 1.0
        for eid in path['edges']:
            product *= edges[eid]['breakdown']['base'] * edges[eid]['breakdown']['factor']
        assert path['confidence'] == pytest.approx(product)


# CS-02 / CS-03 / CS-06 -------------------------------------------------------

def test_path_confidence_is_product_of_steps():
    graph = {'nodes': [], 'edges': [edge('a', 'u', 'm', .9), edge('b', 'm', 'n', .8), edge('c', 'n', 'root', .5)]}
    assert enumerate_paths(graph, ['u'], ['root'], {})[0]['confidence'] == pytest.approx(0.36)


def test_goal_confidence_counts_shared_edges_once():
    graph = {'nodes': [], 'edges': [edge('a', 's', 'm', .5), edge('b', 'm', 'root', .8), edge('c', 'm', 'root', .8)]}
    paths = enumerate_paths(graph, ['s'], ['root'], {})
    assert goal_scores(graph, paths, ['root'], {})[0]['confidence'] == pytest.approx(0.48)
    sampled = goal_scores(graph, paths, ['root'], {'goal_exact_edge_limit': 0})
    assert sampled == goal_scores(graph, paths, ['root'], {'goal_exact_edge_limit': 0})
    assert sampled[0]['confidence'] == pytest.approx(0.48, abs=0.02)


def test_band_thresholds_come_from_config():
    config = {'bands': {'high_min': 0.5, 'medium_min': 0.2}}
    assert [band(v, config) for v in (0.5, 0.4999, 0.2, 0.1999)] == ['High', 'Medium', 'Medium', 'Low']


# NF-05 / fixture regression --------------------------------------------------

@pytest.mark.parametrize('target', sorted(TARGET_CONFIG))
def test_analysis_is_byte_identical_across_runs(target):
    outputs = {dumps(analyze(fixture_snapshot(target), TARGET_CONFIG[target])) for _ in range(5)}
    assert len(outputs) == 1


@pytest.mark.parametrize('target', sorted(TARGET_CONFIG))
def test_committed_analysis_fixtures_match_the_analyzer(target):
    """Fails if KB/graph changes are not followed by tests/fixtures/regenerate.py."""
    snap = fixture_snapshot(target)
    expected = (FIXTURES / f'results/{target}.analysis.json').read_text(encoding='utf-8')
    produced = analyze(snap, TARGET_CONFIG[target])
    validate(produced, 'results', snapshot=snap)
    assert dumps(produced) == expected


def test_build_graph_does_not_mutate_snapshot():
    snap = fixture_snapshot('weak3')
    before = dumps(snap)
    build_graph(snap)
    analyze(snap)
    assert dumps(snap) == before
