"""EC-07: scheduled jobs (cron) and the scripts they run."""
import posixpath

from sable.collect.checks._util import accessors, normalise_mode

MARKER = '##SABLE##'
_INTERPRETERS = {'sh', 'bash', 'dash', 'python', 'python3', 'perl', 'ruby', 'php', 'env'}


def _script_path(command):
    """Pick the script path from a cron command, skipping an interpreter prefix."""
    tokens = [t for t in command.split() if t.startswith('/')]
    for token in tokens:
        if posixpath.basename(token) not in _INTERPRETERS:
            return token
    return tokens[0] if tokens else None


def _emit(jobs, scheduler, run_as, command):
    path = _script_path(command)
    if not path:
        return
    key = (run_as, path)
    if key not in jobs:
        jobs[key] = {'scheduler': scheduler, 'run_as': run_as, 'script_path': path}


def parse_cron(output, scan_user):
    """Parse the combined ``scheduled_jobs`` output into job descriptors.

    Returns a list of ``{scheduler, run_as, script_path}`` dicts. System crontabs
    (/etc/crontab, /etc/cron.d) carry a user field; a user crontab runs as the scan
    user. systemd timers are not resolved to a script here (left as future work).
    """
    sections = output.split(MARKER)
    system = (sections[0] if sections else '') + '\n' + (sections[1] if len(sections) > 1 else '')
    user_crontab = sections[2] if len(sections) > 2 else ''
    jobs = {}

    for raw in system.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' in line.split(' ')[0]:
            continue
        fields = line.split()
        if line.startswith('@'):
            if len(fields) >= 3:
                _emit(jobs, 'cron', fields[1], ' '.join(fields[2:]))
            continue
        if len(fields) >= 7:
            _emit(jobs, 'cron', fields[5], ' '.join(fields[6:]))

    for raw in user_crontab.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' in line.split(' ')[0]:
            continue
        fields = line.split()
        if line.startswith('@') and len(fields) >= 2:
            _emit(jobs, 'cron', scan_user, ' '.join(fields[1:]))
        elif len(fields) >= 6:
            _emit(jobs, 'cron', scan_user, ' '.join(fields[5:]))

    return list(jobs.values())


def assemble_scheduled(jobs, stat_rows, accounts, members=None):
    """Combine job descriptors with ``stat`` output into scheduled_job evidence.

    ``stat_rows`` is ``[(mode, owner, group, path), ...]`` for the job scripts.
    Jobs whose script could not be statted are dropped (the schema needs owner/mode);
    the collector records those as missing checks instead.
    """
    members = members or {}
    account_names = [a['data']['name'] for a in accounts]
    stats = {path: (mode, owner, group) for mode, owner, group, path in stat_rows}
    evidence = []
    for job in jobs:
        path = job['script_path']
        if path not in stats:
            continue
        mode, owner, group = stats[path]
        _readable, writable_by = accessors(mode, owner, group, account_names, members)
        evidence.append({
            'type': 'scheduled_job',
            'data': {
                'scheduler': job['scheduler'],
                'run_as': job['run_as'],
                'script_path': path,
                'script_owner': owner or 'root',
                'script_group': group or 'root',
                'script_mode': normalise_mode(mode),
                'writable_by': writable_by,
            },
            'source_cmd': 'scheduled_jobs',
            'strength': 'observed',
        })
    return evidence
