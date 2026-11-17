"""EC-04: SUID / SGID binaries."""
from sable.collect.checks._util import normalise_mode


def parse_suid(find_output):
    """Parse ``find ... -printf '%m\\t%u\\t%g\\t%p\\n'`` into suid_binary evidence.

    Emits one item per binary carrying the SUID or SGID bit. ``mode`` is the octal
    permission string; ``suid``/``sgid`` are derived from it.
    """
    evidence = []
    for line in find_output.splitlines():
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) != 4:
            continue
        mode, owner, group, path = (p.strip() for p in parts)
        try:
            bits = int(mode, 8)
        except ValueError:
            continue
        suid = bool(bits & 0o4000)
        sgid = bool(bits & 0o2000)
        if not (suid or sgid):
            continue
        evidence.append({
            'type': 'suid_binary',
            'data': {
                'path': path,
                'owner': owner or 'root',
                'group': group or 'root',
                'mode': normalise_mode(mode),
                'suid': suid,
                'sgid': sgid,
            },
            'source_cmd': 'suid_find',
            'strength': 'observed',
        })
    return evidence
