"""RE-07 stable comparison using path structure, not transient path IDs."""


def compare_scans(before, after):
    def index(result):
        edges = {e['id']: e for e in result['graph']['edges']}
        return {(p['entry'], p['goal'], tuple((edges[e]['src'], edges[e]['dst'], edges[e]['rule']) for e in p['edges'])): p for p in result['paths']}
    old, new = index(before), index(after)
    return {'added': [new[k]['id'] for k in sorted(new.keys() - old.keys())],
            'removed': [old[k]['id'] for k in sorted(old.keys() - new.keys())],
            'confidence_changes': [{'before_path': old[k]['id'], 'after_path': new[k]['id'], 'before': old[k]['confidence'], 'after': new[k]['confidence']} for k in sorted(old.keys() & new.keys()) if old[k]['confidence'] != new[k]['confidence']]}
