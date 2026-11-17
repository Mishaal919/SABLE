"""AG-04/CS-02/CS-06: path enumeration, path confidence and confidence bands.

This is the single implementation shared by analysis, planning and residual risk.
Paths are walked over edge IDs (not node pairs) so parallel edges produced by
different rules or evidence stay distinct.
"""
from collections import defaultdict
import hashlib


def band(score, config):
    """CS-06: High at high_min or above, Medium at medium_min or above, Low below."""
    bands = config.get('bands', {})
    return 'High' if score >= bands.get('high_min', .6) else 'Medium' if score >= bands.get('medium_min', .3) else 'Low'


def enumerate_paths(graph, entries, goals, config, known=()):
    """All simple paths of at most path_cutoff edges from each entry to each goal.

    Path confidence is the product of edge likelihoods (step independence).
    Paths already listed in `known` keep their IDs; others get a stable hash ID.
    Output is sorted by ID so repeated runs are identical.
    """
    adjacency = defaultdict(list)
    for edge in sorted(graph['edges'], key=lambda e: e['id']):
        adjacency[edge['src']].append(edge)
    old_ids = {(p['entry'], p['goal'], tuple(p['edges'])): p['id'] for p in known}
    output = []
    cutoff = config.get('path_cutoff', 6)
    if not isinstance(cutoff, int) or cutoff < 1:
        raise ValueError('path_cutoff must be a positive integer')
    def walk(entry, current, goal, visited, edges, confidence):
        if current == goal and edges:
            key = (entry, goal, tuple(edges))
            identifier = old_ids.get(key) or 'p-' + hashlib.sha256(repr(key).encode()).hexdigest()[:16]
            output.append({'id': identifier, 'entry': entry, 'goal': goal, 'edges': edges,
                           'confidence': confidence, 'band': band(confidence, config)})
            return
        if len(edges) >= cutoff:
            return
        for edge in adjacency[current]:
            if edge['dst'] not in visited:
                walk(entry, edge['dst'], goal, visited | {edge['dst']}, edges + [edge['id']], confidence * edge['likelihood'])
    for entry in sorted(set(entries)):
        for goal in sorted(set(goals)):
            walk(entry, entry, goal, {entry}, [], 1.0)
    return sorted(output, key=lambda p: p['id'])
