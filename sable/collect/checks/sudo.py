"""EC-06 / EC-15: sudo rules for the scan user (and full sudoers in elevated mode)."""
import re

_RUNAS = re.compile(r'^\(([^)]*)\)\s*(.*)$')
# A simple sudoers line: user host=(runas[:group]) [NOPASSWD:] commands
_SUDOERS_LINE = re.compile(r'^(\S+)\s+\S+\s*=\s*\(([^)]*)\)\s*(.*)$')


def _runas(raw):
    """Normalise a runas spec like ``root``, ``ALL``, ``root:root`` -> a single name."""
    name = raw.split(':', 1)[0].strip()
    return name or 'root'


def _commands(raw):
    return [c.strip() for c in raw.split(',') if c.strip()]


def parse_sudo_list(stdout, exit_status, scan_user):
    """Parse ``sudo -n -l`` output.

    Returns ``(evidence, password_required)``. ``password_required`` is True when the
    listing could not be obtained without a password; the collector then records a
    ``sudoers_full`` missing check (EC-06 / EC-15 unprivileged behaviour).
    """
    lowered = stdout.lower()
    if exit_status != 0 or 'a password is required' in lowered or 'may run' not in lowered:
        return [], True

    evidence = []
    in_commands = False
    for line in stdout.splitlines():
        if 'may run the following commands' in line.lower():
            in_commands = True
            continue
        if not in_commands:
            continue
        entry = line.strip()
        if not entry:
            continue
        match = _RUNAS.match(entry)
        if not match:
            continue
        runas_raw, rest = match.group(1), match.group(2).strip()
        nopasswd = False
        for tag in ('NOPASSWD:', 'PASSWD:', 'SETENV:'):
            if rest.startswith(tag):
                nopasswd = nopasswd or tag == 'NOPASSWD:'
                rest = rest[len(tag):].strip()
        commands = _commands(rest)
        if not commands:
            continue
        evidence.append({
            'type': 'sudo_rule',
            'data': {
                'user': scan_user,
                'runas': _runas(runas_raw),
                'nopasswd': nopasswd,
                'commands': commands,
            },
            'source_cmd': 'sudo_rules',
            'strength': 'observed',
        })
    return evidence, False


def parse_sudoers(text):
    """Parse an elevated-mode ``/etc/sudoers`` dump into sudo_rule evidence.

    Best-effort: handles ``user host=(runas) [NOPASSWD:] commands`` lines and skips
    Defaults/aliases/comments. Group rules (``%group``) and includes are not expanded.
    """
    evidence = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('Defaults') or '=' not in line:
            continue
        match = _SUDOERS_LINE.match(line)
        if not match:
            continue
        user, runas_raw, rest = match.group(1), match.group(2), match.group(3).strip()
        if user.startswith('%') or '_Alias' in line:
            continue
        nopasswd = 'NOPASSWD:' in rest
        for tag in ('NOPASSWD:', 'PASSWD:', 'SETENV:'):
            rest = rest.replace(tag, ' ')
        commands = _commands(rest)
        if not commands:
            continue
        evidence.append({
            'type': 'sudo_rule',
            'data': {
                'user': user,
                'runas': _runas(runas_raw),
                'nopasswd': nopasswd,
                'commands': commands,
            },
            'source_cmd': 'sudoers_full',
            'strength': 'observed',
        })
    return evidence
