"""Path/scoring adapter for supplied graphs; never constructs attack edges."""
from collections import defaultdict
from itertools import product
import hashlib
import math
import random


def band(score, config):
    bands = config.get('bands', {})
    return 'High' if score >= bands.get('high_min', .6) else 'Medium' if score >= bands.get('medium_min', .3) else 'Low'


def enumerate_paths(graph, entries, goals, config, known=()):
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


def goal_scores(graph, paths, goals, config):
    """Use each independent edge once, including when paths share edges."""
    likelihood = {e['id']: e['likelihood'] for e in graph['edges']}
    output = []
    limit = config.get('goal_exact_edge_limit', 16)
    samples = config.get('goal_samples', 10000)
    if not isinstance(limit, int) or not 0 <= limit <= 20 or not isinstance(samples, int) or samples < 1:
        raise ValueError('Invalid goal scoring limits')
    for goal in sorted(set(goals)):
        routes = [set(p['edges']) for p in paths if p['goal'] == goal]
        ids = sorted(set().union(*routes)) if routes else []
        if not routes:
            score = 0.0
        elif len(ids) <= limit:
            score = 0.0
            for state in product((False, True), repeat=len(ids)):
                enabled = {eid for eid, present in zip(ids, state) if present}
                if any(route <= enabled for route in routes):
                    score += math.prod(likelihood[eid] if present else 1-likelihood[eid] for eid, present in zip(ids, state))
        else:
            rng = random.Random(config.get('random_seed', 0))
            success = 0
            for _ in range(samples):
                enabled = {eid for eid in ids if rng.random() < likelihood[eid]}
                success += any(route <= enabled for route in routes)
            score = success / samples
        output.append({'goal': goal, 'confidence': min(1.0, max(0.0, score))})
    return output


def residual_risk(graph, paths, selected, config):
    blocked = {eid for fix in selected for eid in fix['breaks_edges']}
    remaining = {**graph, 'edges': [e for e in graph['edges'] if e['id'] not in blocked]}
    entries = config.get('entries', sorted({p['entry'] for p in paths}))
    goals = config.get('goals', sorted({p['goal'] for p in paths}))
    new_paths = enumerate_paths(remaining, entries, goals, config, paths)
    return {'paths': new_paths, 'goals': goal_scores(remaining, new_paths, goals, config)}
