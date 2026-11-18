"""EC-12: installed package versions."""


def parse_packages(dpkg_output):
    """Parse ``dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n'``.

    Produces one package evidence item per installed package. The kernel image
    package (``linux-image-<uname -r>``) appears here like any other package, which
    is what the CVE rule matches against.
    """
    evidence = []
    for line in dpkg_output.splitlines():
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        version = parts[1].strip()
        architecture = parts[2].strip() if len(parts) > 2 and parts[2].strip() else 'all'
        if not name or not version:
            continue
        evidence.append({
            'type': 'package',
            'data': {'name': name, 'version': version, 'architecture': architecture},
            'source_cmd': 'installed_packages',
            'strength': 'observed',
        })
    return evidence
