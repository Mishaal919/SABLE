"""Residual-risk adapter for supplied graphs; never constructs attack edges.

Path enumeration, bands and goal scoring live in sable.graph.paths and
sable.score.goal (one shared definition of confidence). They are re-exported
here so existing planner imports keep working.
"""
from sable.graph.paths import band, enumerate_paths
from sable.score.goal import goal_scores

__all__ = ['band', 'enumerate_paths', 'goal_scores', 'residual_risk']


def residual_risk(graph, paths, selected, config):
    blocked = {eid for fix in selected for eid in fix['breaks_edges']}
    remaining = {**graph, 'edges': [e for e in graph['edges'] if e['id'] not in blocked]}
    entries = config.get('entries', sorted({p['entry'] for p in paths}))
    goals = config.get('goals', sorted({p['goal'] for p in paths}))
    new_paths = enumerate_paths(remaining, entries, goals, config, paths)
    return {'paths': new_paths, 'goals': goal_scores(remaining, new_paths, goals, config)}
