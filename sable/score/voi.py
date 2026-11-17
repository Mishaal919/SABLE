"""NV-01: value of information (next best check) for represented unknowns.

For each unknown u with prior p, the goal confidences and the greedy fix set are
recomputed with u true (its edges observed) and u false (its edges removed):

    VOI(u) = p * |change if true| + (1 - p) * |change if false| + bonus

where change is the summed absolute change in goal confidence and the bonus is
added when either scenario changes the top recommended fix. This module calls
the planner's plan_fixes; the planner never calls VOI (no dependency cycle).
"""
from copy import deepcopy
import math

from sable.contracts.validation import ContractError
from sable.graph.paths import enumerate_paths
from sable.score.goal import goal_scores
from sable.score.likelihood import step_likelihood

DEFAULT_VOI_BONUS = 0.1


def _evaluate(graph, entries, goals, candidates, config):
    from sable.fix.planner import plan_fixes
    paths = enumerate_paths(graph, entries, goals, config)
    scores = {g['goal']: g['confidence'] for g in goal_scores(graph, paths, goals, config)}
    present = {edge['id'] for edge in graph['edges']}
    usable = []
    for fix in candidates:
        kept = [eid for eid in fix['breaks_edges'] if eid in present]
        if kept:
            usable.append({**fix, 'breaks_edges': kept})
    plan = plan_fixes(graph, paths, {**config, 'fix_candidates': usable, 'exact_fix_limit': 0})
    greedy = plan['fix_sets']['greedy']
    return scores, greedy[0] if greedy else None


def compute_voi(results, config=None):
    """Ranked VOI list for the results' unknowns; works on analysis or complete results.

    Entries default to the path entries plus the scan account and goals to the
    scored goals; pass 'entries'/'goals' in config to override, as for the planner.
    """
    config = deepcopy(config or {})
    bonus = config.get('voi_bonus', DEFAULT_VOI_BONUS)
    if isinstance(bonus, bool) or not isinstance(bonus, (int, float)) or not math.isfinite(bonus) or bonus < 0:
        raise ContractError('voi_bonus must be a non-negative number')
    config.setdefault('entries', sorted({p['entry'] for p in results['paths']} | {'user:' + results['meta']['user']}))
    config.setdefault('goals', sorted({g['goal'] for g in results['goals']}))
    entries, goals = config['entries'], config['goals']
    graph, candidates = results['graph'], results['fix_candidates']
    base_scores, base_top = _evaluate(graph, entries, goals, candidates, config)
    output = []
    for unknown in sorted(results['unknowns'], key=lambda u: u['id']):
        uid, prior = unknown['id'], unknown['prior']
        true_graph = deepcopy(graph)
        for edge in true_graph['edges']:
            if edge.get('unknown_id') == uid:
                edge['likelihood'], edge['breakdown'] = step_likelihood(edge['breakdown']['base'], 'observed', config)
        false_graph = {**graph, 'edges': [e for e in graph['edges'] if e.get('unknown_id') != uid]}
        true_scores, true_top = _evaluate(true_graph, entries, goals, candidates, config)
        false_scores, false_top = _evaluate(false_graph, entries, goals, candidates, config)
        change_true = sum(abs(true_scores[g] - base_scores[g]) for g in goals)
        change_false = sum(abs(false_scores[g] - base_scores[g]) for g in goals)
        changes_top = true_top != base_top or false_top != base_top
        value = prior * change_true + (1 - prior) * change_false + (bonus if changes_top else 0.0)
        output.append({'unknown': uid, 'value': round(value, 12), 'changes_top_fix': changes_top})
    return sorted(output, key=lambda item: (-item['value'], item['unknown']))
