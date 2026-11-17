"""NV-04: retain expected-case fixes, then cover worst-case unknown edges."""
from copy import deepcopy
from sable.fix.paths import enumerate_paths


def robust_fixes(graph, paths, candidates, selected, config):
    from sable.fix.planner import greedy
    worst = deepcopy(graph)
    for edge in worst['edges']:
        if 'unknown_id' in edge or edge['breakdown']['strength'] == 'unknown':
            edge['likelihood'] = 1.0
    entries = config.get('entries', sorted({p['entry'] for p in paths}))
    goals = config.get('goals', sorted({p['goal'] for p in paths}))
    worst_paths = enumerate_paths(worst, entries, goals, config, paths)
    additional = greedy(candidates, worst_paths, selected)
    return [f['id'] for f in selected] + [f['id'] for f in additional]
