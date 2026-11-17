"""EC-09: file capabilities (getcap)."""


def parse_capabilities(getcap_output):
    """Parse ``getcap -r /`` output into capability evidence.

    Handles both ``/path cap_setuid=ep`` and ``/path = cap_setuid+ep`` forms. The
    capability spec tokens are preserved verbatim so the analyzer's substring match
    (e.g. ``cap_setuid``) still fires.
    """
    evidence = []
    for line in getcap_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Split the path from the capability spec. getcap separates them with ' = '
        # on some versions and a single space on others.
        if ' = ' in line:
            path, spec = line.split(' = ', 1)
        else:
            parts = line.rsplit(' ', 1)
            if len(parts) != 2:
                continue
            path, spec = parts
        path = path.strip()
        caps = [token for token in spec.replace(',', ' ').split() if token]
        if not path or not caps:
            continue
        evidence.append({
            'type': 'capability',
            'data': {'path': path, 'capabilities': caps},
            'source_cmd': 'file_capabilities',
            'strength': 'observed',
        })
    return evidence
