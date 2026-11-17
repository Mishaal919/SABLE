"""Structural and reference validation at every pipeline boundary."""
import json
import math
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker


class ContractError(ValueError):
    """Invalid or inconsistent pipeline data."""


def load_schema(kind):
    if kind not in {'snapshot', 'results'}:
        raise ContractError('Unknown contract kind')
    return json.loads(files('schemas').joinpath(f'{kind}.schema.json').read_text())


def _index(items, label):
    result = {item['id']: item for item in items}
    if len(result) != len(items):
        raise ContractError(f'Duplicate {label} ID')
    return result


def _require(condition, message):
    if not condition:
        raise ContractError(message)


def validate(data, kind, *, snapshot=None):
    """Validate without logging payload values (which may contain sensitive data)."""
    errors = list(Draft202012Validator(load_schema(kind), format_checker=FormatChecker()).iter_errors(data))
    if errors:
        error = errors[0]
        location = '/'.join(str(p) for p in error.absolute_path) or '<root>'
        raise ContractError(f'{kind}: invalid field at {location} ({error.validator})')
    evidence = _index(data['evidence'], 'evidence')
    certificate = data['no_writes']
    _require(certificate['status'] != 'passed' or (certificate['method'] != 'none' and not certificate['unexpected_changes']), 'Invalid passing no-writes certificate')
    if kind == 'snapshot':
        return
    nodes = _index(data['graph']['nodes'], 'node')
    edges = _index(data['graph']['edges'], 'edge')
    unknowns = _index(data['unknowns'], 'unknown')
    candidates = _index(data['fix_candidates'], 'candidate fix')
    fixes = _index(data['fixes'], 'fix')
    for edge in edges.values():
        _require(edge['src'] in nodes and edge['dst'] in nodes, 'Edge references missing node')
        _require(set(edge['evidence_ids']) <= evidence.keys(), 'Edge references missing evidence')
        _require('unknown_id' not in edge or edge['unknown_id'] in unknowns, 'Edge references missing unknown')
        b = edge['breakdown']
        _require(math.isclose(edge['likelihood'], b['base'] * b['factor'], abs_tol=1e-9), 'Edge likelihood does not match breakdown')
    def check_paths(paths, blocked=frozenset()):
        _index(paths, 'path')
        for path in paths:
            current, score, visited = path['entry'], 1.0, {path['entry']}
            _require(current in nodes and path['goal'] in nodes, 'Path references missing node')
            for eid in path['edges']:
                _require(eid in edges and eid not in blocked, 'Path references missing or blocked edge')
                edge = edges[eid]
                _require(edge['src'] == current, 'Path edges are not contiguous')
                current = edge['dst']
                _require(current not in visited, 'Path must be simple')
                visited.add(current)
                score *= edge['likelihood']
            _require(current == path['goal'], 'Path does not reach its goal')
            _require(math.isclose(score, path['confidence'], abs_tol=1e-9), 'Path confidence does not match edge product')
    check_paths(data['paths'])
    for goal in data['goals']:
        _require(goal['goal'] in nodes, 'Goal references missing node')
    for fix in candidates.values():
        _require(set(fix['breaks_edges']) <= edges.keys(), 'Fix references missing edge')
    for fid, fix in fixes.items():
        _require(fid in candidates, 'Ranked fix is not a candidate')
        _require({k:v for k,v in fix.items() if k != 'risk_removed'} == candidates[fid], 'Ranked fix differs from candidate')
    for name, selected in data['fix_sets'].items():
        _require(selected is None or set(selected) <= candidates.keys(), f'{name} references missing fix')
    greedy = data['fix_sets']['greedy']
    _require(greedy == [f['id'] for f in data['fixes']], 'Ranked fixes must match greedy order')
    risks = [f['risk_removed'] for f in data['fixes']]
    _require(risks == sorted(risks, reverse=True), 'Marginal risk must not increase')
    for item in data['voi']:
        _require(item['unknown'] in unknowns, 'VOI references missing unknown')
    if data['residual'] is not None:
        blocked = {eid for fid in greedy for eid in candidates[fid]['breaks_edges']}
        check_paths(data['residual']['paths'], blocked)
        for goal in data['residual']['goals']:
            _require(goal['goal'] in nodes, 'Residual goal references missing node')
    if snapshot is not None:
        validate(snapshot, 'snapshot')
        for key in ('evidence', 'missing', 'no_writes'):
            _require(data[key] == snapshot[key], f'Results changed snapshot {key}')
        _require({k:v for k,v in data['meta'].items() if k not in ('kb_version', 'kb_date')} == snapshot['meta'], 'Results changed snapshot metadata')


def dumps(data):
    """Stable object key ordering; producers must order semantic lists explicitly."""
    return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
