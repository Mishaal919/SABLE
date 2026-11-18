"""EC-08: running services, listening ports and (best-effort) versions."""
import re

MARKER = '##SABLE##'
_PROC = re.compile(r'"([^"]+)"')


def _split_host_port(endpoint):
    """Split ``address:port`` handling IPv6 ``[::]:22`` and ``*:22``."""
    endpoint = endpoint.strip()
    if endpoint.startswith('['):
        host, _, port = endpoint[1:].partition(']:')
        return host or '::', port
    host, _, port = endpoint.rpartition(':')
    return (host or '0.0.0.0'), port


def parse_services(ss_output, systemd_output='', package_map=None):
    """Parse ``ss -tulpnH`` and ``systemctl`` output into service evidence.

    Listeners are grouped by process name. ``package_map`` optionally supplies
    ``name -> (package, version)``; otherwise both are null (allowed by the schema).
    Services that are running but not listening are still emitted with no listeners.
    """
    package_map = package_map or {}
    services = {}

    for line in ss_output.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        netid = fields[0].lower()
        protocol = 'udp' if netid.startswith('udp') else 'tcp'
        host, port = _split_host_port(fields[4])
        if not port.isdigit():
            continue
        match = _PROC.search(line)
        name = match.group(1) if match else 'unknown'
        service = services.setdefault(name, {'name': name, 'running': True, 'listeners': []})
        listener = {'address': host, 'port': int(port), 'protocol': protocol}
        if listener not in service['listeners']:
            service['listeners'].append(listener)

    for line in systemd_output.splitlines():
        fields = line.split()
        if not fields:
            continue
        unit = fields[0]
        if not unit.endswith('.service'):
            continue
        name = unit[:-len('.service')]
        services.setdefault(name, {'name': name, 'running': True, 'listeners': []})

    evidence = []
    for name in sorted(services):
        service = services[name]
        service['listeners'].sort(key=lambda listener: (listener['protocol'], listener['address'], listener['port']))
        package, version = package_map.get(name, (None, None))
        evidence.append({
            'type': 'service',
            'data': {
                'name': name,
                'package': package,
                'version': version,
                'running': service['running'],
                'listeners': service['listeners'],
            },
            'source_cmd': 'services',
            'strength': 'observed',
        })
    return evidence
