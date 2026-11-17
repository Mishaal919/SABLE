"""CS-03: goal confidence that counts shared edges once."""
from itertools import product
import math
import random


def goal_scores(graph, paths, goals, config):
    """Probability that at least one path to each goal succeeds.

    Each distinct edge is an independent event used once, so paths sharing an
    edge are not double counted (shared 0.5 then parallel 0.8/0.8 gives 0.48).
    Up to goal_exact_edge_limit edges are enumerated exactly; larger cases use
    goal_samples Monte Carlo draws with a local RNG seeded by random_seed.
    """
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
