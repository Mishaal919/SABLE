"""EC-03: system identity -> snapshot meta fields."""
import re

MARKER = '##SABLE##'


def _os_release(text):
    values = {}
    for line in text.splitlines():
        if '=' in line:
            key, _, value = line.partition('=')
            values[key.strip()] = value.strip().strip('"\'')
    distro_id = values.get('ID', '').lower()
    version = values.get('VERSION_ID', '')
    name = ' '.join(part for part in (distro_id, version) if part)
    return name or values.get('PRETTY_NAME', 'unknown')


def _id_fields(text):
    user = ''
    match = re.search(r'uid=\d+\(([^)]+)\)', text)
    if match:
        user = match.group(1)
    groups = [name for _gid, name in re.findall(r'(\d+)\(([^)]+)\)', _after_groups(text))]
    # The uid/gid prefix of the `id` line also matches; keep only the groups= section.
    return user, sorted(dict.fromkeys(groups))


def _after_groups(text):
    match = re.search(r'groups=(.*)', text)
    return match.group(1) if match else ''


def parse_identity(output):
    """Return meta fields from the combined ``system_identity`` output.

    Raises ValueError if the scan user cannot be determined (EC-03 / CONTRACTS:
    never fabricate identity).
    """
    sections = output.split(MARKER)
    os_release = sections[0] if len(sections) > 0 else ''
    kernel = sections[1].strip() if len(sections) > 1 else ''
    arch = sections[2].strip() if len(sections) > 2 else ''
    id_output = sections[3] if len(sections) > 3 else ''

    user, groups = _id_fields(id_output)
    if not user:
        raise ValueError('could not determine the scan user from `id` output')
    if not kernel:
        raise ValueError('could not determine the kernel from `uname -r`')
    meta = {
        'distro': _os_release(os_release),
        'kernel': kernel,
        'user': user,
        'groups': groups or [user],
    }
    if arch:
        meta['architecture'] = arch
    return meta
