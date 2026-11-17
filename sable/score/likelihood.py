"""CS-01/CS-05: step likelihood = base x strength factor, with config defaults."""
import math

from sable.contracts.validation import ContractError

DEFAULT_STRENGTH_FACTORS = {'observed': 1.0, 'inferred': 0.6, 'unknown': 0.3}
STRENGTH_ORDER = ('unknown', 'inferred', 'observed')


def strength_factors(config):
    """Merge configured strength factors over the defaults and check their range."""
    factors = {**DEFAULT_STRENGTH_FACTORS, **(config or {}).get('strength_factors', {})}
    if set(factors) != set(DEFAULT_STRENGTH_FACTORS):
        raise ContractError('strength_factors may only define observed, inferred and unknown')
    for value in factors.values():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ContractError('Strength factors must be numbers between 0 and 1')
    return factors


def weakest(strengths):
    """The combined strength of a step is that of its weakest supporting evidence."""
    return min(strengths, key=STRENGTH_ORDER.index)


def cvss_base(score):
    """CVE steps use the CVSS base score scaled to 0..1 as their base likelihood."""
    return round(score / 10, 4)


def step_likelihood(base, strength, config=None):
    """Return (likelihood, breakdown) for one edge; breakdown is stored on the edge (CS-04)."""
    if isinstance(base, bool) or not isinstance(base, (int, float)) or not 0 <= base <= 1:
        raise ContractError('Base likelihood must be between 0 and 1')
    if strength not in STRENGTH_ORDER:
        raise ContractError('Unknown evidence strength')
    factor = strength_factors(config)[strength]
    return base * factor, {'base': base, 'strength': strength, 'factor': factor}
