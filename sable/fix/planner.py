"""Pure, deterministic fix planning; no SSH, command execution or VOI calls."""
from copy import deepcopy
from string import Formatter

from jsonschema import Draft202012Validator
from sable.contracts.validation import ContractError, load_schema, validate
from sable.fix.exact import exact_fixes
from sable.fix.paths import band, enumerate_paths, goal_scores, residual_risk


def _config(config):
    import math
    result = deepcopy(config)
    bands = {'high_min': .6, 'medium_min': .3, **result.get('bands', {})}
    if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in bands.values()) or not 0 <= bands['medium_min'] <= bands['high_min'] <= 1:
        raise ContractError('Confidence thresholds must satisfy 0 <= Medium <= High <= 1')
    result['bands'] = bands
    for key in ('entries', 'goals'):
        if key in result and (not isinstance(result[key], list) or not all(isinstance(x, str) for x in result[key])):
            raise ContractError(f'{key} must be a list of node IDs')
    return result


def _validate_graph_paths(graph, paths):
    import math
    schema = load_schema('results')['properties']
    if not Draft202012Validator(schema['graph']).is_valid(graph) or not Draft202012Validator(schema['paths']).is_valid(paths):
        raise ContractError('Invalid graph or path structure')
    nodes = {n['id'] for n in graph['nodes']}
    edges = {e['id']: e for e in graph['edges']}
    if len(nodes) != len(graph['nodes']) or len(edges) != len(graph['edges']) or len({p['id'] for p in paths}) != len(paths):
        raise ContractError('Duplicate graph or path ID')
    for edge in edges.values():
        if edge['src'] not in nodes or edge['dst'] not in nodes:
            raise ContractError('Edge references missing node')
    for path in paths:
        current, probability, seen = path['entry'], 1.0, {path['entry']}
        for eid in path['edges']:
            if eid not in edges or edges[eid]['src'] != current or edges[eid]['dst'] in seen:
                raise ContractError('Invalid simple path or missing edge')
            current = edges[eid]['dst']
            seen.add(current)
            probability *= edges[eid]['likelihood']
        if current != path['goal'] or not math.isclose(probability, path['confidence'], abs_tol=1e-9):
            raise ContractError('Path goal or confidence does not match its edges')


def build_candidates(graph, evidence, templates):
    """Instantiate per-rule templates using one evidence record's data per edge.

    templates[rule] has type, description, command and rollback. Simple {field}
    placeholders reference evidence.data plus src/dst/rule. Commands are display
    material only. Equal rendered fixes merge their edge mappings.
    """
    import hashlib
    records = {e['id']: e for e in evidence}
    merged = {}
    for edge in sorted(graph['edges'], key=lambda e: e['id']):
        template = templates.get(edge['rule'])
        if template is None:
            continue
        if not template.get('rollback'):
            raise ContractError('Every KB fix template requires a rollback')
        for eid in edge['evidence_ids']:
            if eid not in records:
                raise ContractError('Template references missing evidence')
            context = {**records[eid]['data'], 'src': edge['src'], 'dst': edge['dst'], 'rule': edge['rule']}
            def render(field):
                value = template[field]
                for _, key, spec, conversion in Formatter().parse(value):
                    if key is not None and (not key.isidentifier() or spec or conversion):
                        raise ContractError('Fix templates allow simple named placeholders only')
                try:
                    return value.format_map(context)
                except KeyError as exc:
                    raise ContractError('Fix template requires unavailable evidence data') from exc
            item = {key: render(key) for key in ('description', 'command', 'rollback')}
            item['type'] = template['type']
            item['execution'] = 'script_and_apply' if item['type'] in ('chmod', 'chown') else 'recommend_only'
            key = tuple(item[k] for k in ('type', 'command', 'rollback', 'description'))
            if key not in merged:
                merged[key] = {**item, 'id': 'f-' + hashlib.sha256(repr(key).encode()).hexdigest()[:16], 'breaks_edges': []}
            merged[key]['breaks_edges'].append(edge['id'])
    for item in merged.values():
        item['breaks_edges'] = sorted(set(item['breaks_edges']))
    return sorted(merged.values(), key=lambda f: f['id'])


def _candidates(graph, config):
    candidates = deepcopy(config.get('fix_candidates', []))
    schema = load_schema('results')['$defs']['candidate']
    edge_ids = {e['id'] for e in graph['edges']}
    seen = set()
    for fix in candidates:
        if not Draft202012Validator(schema).is_valid(fix):
            raise ContractError('Invalid candidate fix (including required rollback)')
        if fix['id'] in seen or not set(fix['breaks_edges']) <= edge_ids:
            raise ContractError('Duplicate fix ID or unknown edge in candidate')
        seen.add(fix['id'])
    return sorted(candidates, key=lambda f: f['id'])


def greedy(candidates, paths, initial=()):
    remaining = [p for p in paths if p['band'] in ('High', 'Medium')]
    selected, used = [], set()
    for fix in initial:
        used.add(fix['id'])
        remaining = [p for p in remaining if not set(p['edges']) & set(fix['breaks_edges'])]
    while remaining:
        ranked = []
        for fix in candidates:
            if fix['id'] not in used:
                reduction = sum(p['confidence'] for p in remaining if set(p['edges']) & set(fix['breaks_edges']))
                ranked.append((-reduction, fix['id'], fix))
        if not ranked:
            break
        negative, _, fix = min(ranked, key=lambda row: row[:2])
        if negative >= 0:
            break
        selected.append({**deepcopy(fix), 'risk_removed': -negative})
        used.add(fix['id'])
        remaining = [p for p in remaining if not set(p['edges']) & set(fix['breaks_edges'])]
    return selected


def plan_fixes(graph, paths, config):
    """RP-02 public API. graph is the contract mapping; config supplies candidates."""
    config = _config(config)
    _validate_graph_paths(graph, paths)
    candidates = _candidates(graph, config)
    paths = sorted(deepcopy(paths), key=lambda p: p['id'])
    for path in paths:
        path['band'] = band(path['confidence'], config)
    selected = greedy(candidates, paths)
    exact, exact_status = exact_fixes(candidates, paths, config.get('exact_fix_limit', 15))
    high_greedy = greedy(candidates, [p for p in paths if p['band'] == 'High'])
    from sable.fix.robust import robust_fixes
    robust = robust_fixes(graph, paths, candidates, selected, config)
    breakable = sum(p['confidence'] for p in paths if p['band'] in ('High', 'Medium') and any(set(p['edges']) & set(f['breaks_edges']) for f in candidates))
    total = 0.0
    curve = [{'fix_count': 0, 'risk_removed': 0.0, 'percent': 0.0}]
    for index, fix in enumerate(selected, 1):
        total += fix['risk_removed']
        curve.append({'fix_count': index, 'risk_removed': total, 'percent': min(100.0, 100 * total / breakable) if breakable else 0.0})
    return {'fixes': selected, 'fix_sets': {'greedy': [f['id'] for f in selected], 'exact': exact, 'robust': robust},
            'planning': {'exact_status': exact_status, 'high_only_greedy': [f['id'] for f in high_greedy],
                         'breakable_risk': breakable, 'risk_curve': curve,
                         'bands': config.get('bands', {'high_min': .6, 'medium_min': .3}),
                         'path_cutoff': config.get('path_cutoff', 6)}}


def finalize_results(analysis, config=None):
    """Complete results using a supplied attack graph; never generates edges."""
    validate(analysis, 'results')
    output = deepcopy(analysis)
    config = _config(config or {})
    if 'fix_templates' in config:
        output['fix_candidates'] = build_candidates(output['graph'], output['evidence'], config['fix_templates'])
    config['fix_candidates'] = output['fix_candidates']
    config.setdefault('entries', sorted({p['entry'] for p in output['paths']} | {'user:' + output['meta']['user']}))
    config.setdefault('goals', sorted({g['goal'] for g in output['goals']} | ({'root'} if any(n['id'] == 'root' for n in output['graph']['nodes']) else set())))
    output['paths'] = enumerate_paths(output['graph'], config['entries'], config['goals'], config, output['paths'])
    output['goals'] = goal_scores(output['graph'], output['paths'], config['goals'], config)
    plan = plan_fixes(output['graph'], output['paths'], config)
    output.update(plan)
    output['residual'] = residual_risk(output['graph'], output['paths'], output['fixes'], config)
    output['stage'] = 'complete'
    validate(output, 'results')
    return output
