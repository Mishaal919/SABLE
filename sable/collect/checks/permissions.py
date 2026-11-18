"""EC-05: sensitive file permissions and world-writable files."""
from sable.collect.checks._util import accessors, normalise_mode, parse_stat_lines


def _file_permission(mode, owner, group, path, account_names, members):
    readable_by, writable_by = accessors(mode, owner, group, account_names, members)
    return {
        'type': 'file_permission',
        'data': {
            'path': path,
            'owner': owner or 'root',
            'group': group or 'root',
            'mode': normalise_mode(mode),
            'writable_by': writable_by,
            'readable_by': readable_by,
        },
        'source_cmd': 'sensitive_permissions',
        'strength': 'observed',
    }


def parse_permissions(stat_output, accounts, members=None):
    """Parse sensitive-path ``stat`` output into file_permission evidence.

    ``accounts`` is the list of parsed user_account evidence; ``members`` maps group
    name -> member set (from :func:`_util.group_members`).
    """
    account_names = [a['data']['name'] for a in accounts]
    members = members or {}
    evidence = []
    for mode, owner, group, path in parse_stat_lines(stat_output):
        evidence.append(_file_permission(mode, owner, group, path, account_names, members))
    return evidence


def parse_world_writable(find_output, accounts, members=None):
    """Parse world-writable ``find -printf`` output into file_permission evidence."""
    account_names = [a['data']['name'] for a in accounts]
    members = members or {}
    evidence = []
    for line in find_output.splitlines():
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) != 4:
            continue
        mode, owner, group, path = (p.strip() for p in parts)
        evidence.append(_file_permission(mode, owner, group, path, account_names, members))
    return evidence
