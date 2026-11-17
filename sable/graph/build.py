"""AG-01..AG-06: build the attack graph from a snapshot and produce analysis results.

The graph is the JSON mapping defined in schemas/results.schema.json (nodes and
edges), so the planner, reporter and VOI all share it without adapters. Every edge
is created from catalogue rules and cites the evidence that supports it.
"""
from copy import deepcopy
from fnmatch import fnmatchcase
import posixpath
import re
from string import Formatter

from sable.contracts.validation import ContractError, validate
from sable.graph.paths import enumerate_paths
from sable.kb.loader import KnowledgeBaseError, load_kb
from sable.kb.versions import compare_versions
from sable.score.goal import goal_scores
from sable.score.likelihood import cvss_base, step_likelihood, strength_factors, weakest

INTERACTIVE_MIN_UID = 1000
DISABLED_SHELLS = ('nologin', 'false')
LOOPBACK_PREFIXES = ('127.', '::1', 'localhost')
DEFAULT_UNKNOWN_PRIOR = 0.5


def node_id(text):
    """Normalise a state name; user:root is the root node."""
    return 'root' if text in ('root', 'user:root') else text


def node_kind(identifier):
    if identifier.startswith('asset:'):
        return 'asset'
    if identifier.startswith('cred:'):
        return 'credential'
    return 'privilege'


def _account_node(name):
    return node_id(name if name.startswith(('user:', 'asset:', 'cred:', 'service:')) or name == 'root' else 'user:' + name)


def _goal_node(name):
    if name == 'root' or name.startswith(('asset:', 'cred:', 'user:')):
        return node_id(name)
    return 'asset:' + name


def analysis_config(config):
    """Accept flat scoring.yaml keys plus sable.yaml's scan section; validate types."""
    config = deepcopy(config or {})
    if not isinstance(config, dict):
        raise ContractError('Analysis config must be a mapping')
    scan = config.pop('scan', None) or {}
    for key in ('extra_entry_points', 'asset_goals'):
        if key in scan:
            config.setdefault(key, scan[key])
        value = config.setdefault(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise ContractError(f'{key} must be a list of names')
    strength_factors(config)
    prior = config.setdefault('unknown_prior', DEFAULT_UNKNOWN_PRIOR)
    if isinstance(prior, bool) or not isinstance(prior, (int, float)) or not 0 <= prior <= 1:
        raise ContractError('unknown_prior must be between 0 and 1')
    return config


def _values(value):
    return value if isinstance(value, list) else [value]


def _render(text, context, rule_id):
    for _, key, spec, conversion in Formatter().parse(text):
        if key is not None and (not key.isidentifier() or spec or conversion):
            raise KnowledgeBaseError(f'rule {rule_id}: templates allow simple named placeholders only')
    try:
        return text.format_map(context)
    except KeyError as exc:
        raise KnowledgeBaseError(f'rule {rule_id}: template field {exc.args[0]!r} is not in the evidence data') from exc


def _condition(data, condition):
    if condition['field'] not in data:
        return False
    value, op, expected = data[condition['field']], condition['op'], condition['value']
    if op == 'eq':
        return value == expected
    if op == 'ne':
        return value != expected
    if op == 'in':
        return value in _values(expected)
    if op in ('glob', 'not_glob'):
        matched = isinstance(value, str) and any(fnmatchcase(value, pattern) for pattern in _values(expected))
        return matched if op == 'glob' else not matched
    return any(isinstance(item, str) and str(expected) in item for item in _values(value))


def binary_entry(kb, command):
    """Catalogue entry for a path or command line, matching versioned names (python3.10)."""
    words = command.strip().split()
    base = posixpath.basename(words[0]) if words else ''
    for name in (base, re.sub(r'[\d.]+$', '', base)):
        if name in kb['binaries']:
            return kb['binaries'][name]
    return None


def _binary_matches(kb, value, spec):
    for item in _values(value):
        if not isinstance(item, str):
            continue
        if spec.get('allow_all') and item.strip() == 'ALL':
            return True
        entry = binary_entry(kb, item)
        if entry and spec['context'] in entry['contexts']:
            return True
    return False


def _interactive(record, scan_user):
    data = record['data']
    return (record['type'] == 'user_account' and data['uid'] >= INTERACTIVE_MIN_UID and data['name'] != scan_user
            and posixpath.basename(data['shell']) not in DISABLED_SHELLS)


class GraphBuilder:
    """Collects nodes and edges; refuses edges without resolvable evidence (AG-05)."""

    def __init__(self, evidence, config):
        self.evidence = {item['id']: item for item in evidence}
        self.order = {item['id']: index for index, item in enumerate(evidence)}
        self.config = config
        self.nodes = {}
        self.edges = {}

    def add_node(self, identifier, possible_entry=False):
        node = self.nodes.setdefault(identifier, {'id': identifier, 'kind': node_kind(identifier)})
        if possible_entry:
            node['possible_entry'] = True

    def add_edge(self, src, dst, rule, evidence_ids, base, strength, attack, cis=None, unknown=None):
        if not evidence_ids:
            raise ContractError(f'Edge for rule {rule} has no evidence IDs')
        missing = [eid for eid in evidence_ids if eid not in self.evidence]
        if missing:
            raise ContractError(f'Edge for rule {rule} cites evidence not in the snapshot')
        src, dst = node_id(src), node_id(dst)
        if src == dst or src == 'root':
            return
        ordered = sorted(set(evidence_ids), key=self.order.__getitem__)
        key = (src, dst, rule, tuple(ordered))
        if key in self.edges:
            return
        likelihood, breakdown = step_likelihood(base, strength, self.config)
        edge = {'src': src, 'dst': dst, 'rule': rule, 'evidence_ids': ordered, 'attack': attack,
                'likelihood': likelihood, 'breakdown': breakdown}
        if cis:
            edge['cis'] = cis
        if unknown:
            edge['unknown'] = unknown
        self.add_node(src)
        self.add_node(dst)
        self.edges[key] = edge


def _apply_match_rule(builder, rule, records, kb, entries):
    for record in records:
        if record['type'] != rule['evidence_type']:
            continue
        data = record['data']
        if not all(_condition(data, condition) for condition in rule['when']):
            continue
        if 'binary' in rule and not _binary_matches(kb, data.get(rule['binary']['field']), rule['binary']):
            continue
        target = node_id(_render(rule['target'], data, rule['id']))
        if rule['actors'] == 'entries':
            actors = entries
        else:
            actors = [_account_node(name) for name in _values(data.get(rule['actors']['field'], [])) if isinstance(name, str)]
        for actor in actors:
            builder.add_edge(actor, target, rule['id'], [record['id']], rule['base'], record['strength'],
                             rule['attack'], rule.get('cis'))


def _apply_credential_reuse(builder, rule, records, scan_user):
    credentials = [r for r in records if r['type'] == 'credential_location' and r['data']['pattern_type'] == 'password']
    accounts = [r for r in records if _interactive(r, scan_user)]
    for credential in credentials:
        for account in accounts:
            strength = weakest([credential['strength'], account['strength'], 'inferred'])
            builder.add_edge('cred:' + credential['data']['path'], 'user:' + account['data']['name'], rule['id'],
                             [credential['id'], account['id']], rule['base'], strength, rule['attack'], rule.get('cis'))


def _apply_unknown_sudo(builder, rule, records, missing, scan_user):
    if not any(item['check'] == rule['missing_check'] for item in missing):
        return
    known = {r['data']['user'] for r in records if r['type'] == 'sudo_rule'}
    for account in records:
        if _interactive(account, scan_user) and account['data']['name'] not in known:
            name = account['data']['name']
            builder.add_edge('user:' + name, 'root', rule['id'], [account['id']], rule['base'], 'unknown',
                             rule['attack'], rule.get('cis'), unknown=(rule['missing_check'], name))


def _apply_cves(builder, rule, records, kb, meta, entries, templates):
    distro = meta['distro'].strip().lower()
    packages = [r for r in records if r['type'] == 'package']
    for cve in sorted(kb['cves'].values(), key=lambda c: c['id']):
        wanted = 'linux-image-' + meta['kernel'] if cve['package'] == 'kernel' else cve['package']
        for affected in cve['affected']:
            if affected['distro'] != distro:
                continue
            for record in packages:
                if record['data']['name'] != wanted:
                    continue
                version = record['data']['version']
                try:
                    vulnerable = compare_versions(version, affected['fixed']) < 0 and (
                        'introduced' not in affected or compare_versions(version, affected['introduced']) >= 0)
                except ValueError:
                    continue
                if not vulnerable:
                    continue
                fix = {key: value.replace('{cve}', cve['id']).replace('{fixed}', affected['fixed'])
                       for key, value in rule['fix'].items()}
                templates[cve['id']] = fix
                strength = weakest([record['strength'], 'inferred'])
                for actor in entries:
                    builder.add_edge(actor, 'root', cve['id'], [record['id']], cvss_base(cve['cvss']['score']),
                                     strength, rule['attack'], rule.get('cis'))


def build_graph(snapshot, kb=None, config=None):
    """Return graph, entries, goals, unknowns and fix templates for one snapshot.

    Only nodes reachable from the entry points are kept (plus root, configured
    goals and possible-entry service nodes), so the cron path in weak2 appears only
    when www-data is configured as an entry (AG-02).
    """
    kb = load_kb() if kb is None else kb
    config = analysis_config(config)
    meta, records = snapshot['meta'], snapshot['evidence']
    entries = sorted({_account_node('user:' + meta['user'])} | {_account_node(name) for name in config['extra_entry_points']})
    builder = GraphBuilder(records, config)
    templates = {}
    for rule in sorted(kb['rules'].values(), key=lambda r: r['id']):
        if rule['kind'] == 'match':
            _apply_match_rule(builder, rule, records, kb, entries)
        elif rule['kind'] == 'credential_reuse':
            _apply_credential_reuse(builder, rule, records, meta['user'])
        elif rule['kind'] == 'unknown_sudo':
            _apply_unknown_sudo(builder, rule, records, snapshot['missing'], meta['user'])
        else:
            _apply_cves(builder, rule, records, kb, meta, entries, templates)
        if rule['kind'] != 'cve':
            templates[rule['id']] = rule['fix']

    reachable, frontier = set(entries), list(entries)
    while frontier:
        current = frontier.pop()
        for edge in builder.edges.values():
            if edge['src'] == current and edge['dst'] not in reachable:
                reachable.add(edge['dst'])
                frontier.append(edge['dst'])
    kept = [edge for edge in builder.edges.values() if edge['src'] in reachable]

    goals = {'root'} | {n for n in reachable if node_kind(n) in ('asset', 'credential')}
    goals |= {_goal_node(name) for name in config['asset_goals']}
    nodes = {}
    for identifier in sorted(reachable | goals):
        nodes[identifier] = {'id': identifier, 'kind': node_kind(identifier)}
    for record in records:
        if record['type'] == 'service' and record['data']['running'] and any(
                not listener['address'].startswith(LOOPBACK_PREFIXES) for listener in record['data']['listeners']):
            identifier = 'service:' + record['data']['name']
            nodes.setdefault(identifier, {'id': identifier, 'kind': 'privilege'})['possible_entry'] = True

    kept.sort(key=lambda e: ([builder.order[eid] for eid in e['evidence_ids']], e['rule'], e['src'], e['dst']))
    width = max(2, len(str(len(kept))))
    unknown_keys = sorted({edge['unknown'] for edge in kept if 'unknown' in edge})
    unknown_ids = {key: f'u-{index:0{width}d}' for index, key in enumerate(unknown_keys, 1)}
    edges = []
    for index, edge in enumerate(kept, 1):
        edge = deepcopy(edge)
        edge['id'] = f'e-{index:0{width}d}'
        if 'unknown' in edge:
            edge['unknown_id'] = unknown_ids[edge.pop('unknown')]
        edges.append(edge)
    unknowns = [{'id': unknown_ids[key], 'prior': config['unknown_prior'], 'resolving_check': key[0]} for key in unknown_keys]
    graph = {'nodes': [nodes[n] for n in sorted(nodes)], 'edges': edges}
    return {'graph': graph, 'entries': entries, 'goals': sorted(goals), 'unknowns': unknowns, 'templates': templates}


def _number(items, prefix, key):
    width = max(2, len(str(len(items))))
    ordered = sorted(items, key=key)
    return {item['id']: f'{prefix}-{index:0{width}d}' for index, item in enumerate(ordered, 1)}


def analyze(snapshot, config=None, kb=None):
    """Snapshot -> validated results with stage 'analysis' (no SSH, no planning).

    Includes paths, shared-edge goal confidence, represented unknowns and candidate
    fixes instantiated from the KB templates by the planner's build_candidates.
    """
    from sable.fix.planner import build_candidates
    validate(snapshot, 'snapshot')
    kb = load_kb() if kb is None else kb
    config = analysis_config(config)
    built = build_graph(snapshot, kb, config)
    graph = built['graph']
    paths = enumerate_paths(graph, built['entries'], built['goals'], config)
    renamed = _number(paths, 'p', lambda p: (-p['confidence'], p['entry'], p['goal'], p['edges']))
    for path in paths:
        path['id'] = renamed[path['id']]
    paths.sort(key=lambda p: p['id'])
    position = {edge['id']: index for index, edge in enumerate(graph['edges'])}
    candidates = build_candidates(graph, snapshot['evidence'], built['templates'])
    renamed = _number(candidates, 'f', lambda f: (min(position[e] for e in f['breaks_edges']), f['id']))
    for fix in candidates:
        fix['id'] = renamed[fix['id']]
    candidates.sort(key=lambda f: f['id'])
    meta = {**deepcopy(snapshot['meta']), 'kb_version': kb['meta']['version'], 'kb_date': kb['meta']['date']}
    results = {
        'schema_version': '1.0', 'stage': 'analysis', 'meta': meta,
        'evidence': deepcopy(snapshot['evidence']), 'missing': deepcopy(snapshot['missing']),
        'no_writes': deepcopy(snapshot['no_writes']), 'graph': graph, 'paths': paths,
        'goals': goal_scores(graph, paths, built['goals'], config), 'unknowns': built['unknowns'],
        'voi': [], 'fix_candidates': candidates, 'fixes': [],
        'fix_sets': {'greedy': [], 'exact': None, 'robust': None}, 'residual': None,
    }
    validate(results, 'results', snapshot=snapshot)
    return results
