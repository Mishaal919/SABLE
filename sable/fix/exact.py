"""RP-03: exhaustive minimum-cardinality coverage of High paths."""
from itertools import combinations


def exact_fixes(candidates, paths, limit=15):
    if not isinstance(limit, int) or not 0 <= limit <= 15:
        raise ValueError('exact_fix_limit must be between 0 and 15')
    if len(candidates) > limit:
        return None, 'skipped_limit'
    high = [set(p['edges']) for p in paths if p['band'] == 'High']
    ordered = sorted(candidates, key=lambda f: f['id'])
    for size in range(len(ordered) + 1):
        for subset in combinations(ordered, size):
            blocked = {edge for fix in subset for edge in fix['breaks_edges']}
            if all(path & blocked for path in high):
                return [fix['id'] for fix in subset], 'optimal'
    return None, 'uncoverable'
