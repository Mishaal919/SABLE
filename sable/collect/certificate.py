"""NV-02: no-writes certificate.

Compares a filesystem fingerprint taken before and after a scan and classifies each
changed path as expected (a login/audit log that any SSH session touches) or
unexpected. A certificate only ``passed`` when a real method ran and nothing
unexpected changed; otherwise it is ``failed`` or, when no fingerprint was taken,
``not_run`` (the honest default the collector writes today).
"""
# Login/audit records and runtime artifacts an ordinary SSH session (with a
# read-only sudo -n probe) legitimately creates or updates. A scan touching only
# these is non-destructive; anything else is flagged.
EXPECTED_CHANGES = (
    '/var/log/auth.log',
    '/var/log/wtmp',
    '/var/log/lastlog',
    '/var/log/btmp',
    '/var/log/journal',
    '/var/log/secure',
    '/run/utmp',
    '/run/motd.dynamic',
    '/run/sshd.pid',
    '/run/sshd',
    '/run/sudo',
    '/run/lock',
)


def _is_login_cache(path):
    # PAM/motd writes a per-user "legal displayed" marker under ~/.cache on login.
    return '/.cache' in path and ('motd' in path or path.rstrip('/').endswith('.cache'))


def not_run():
    """The honest default certificate before any fingerprinting is implemented."""
    return {'status': 'not_run', 'method': 'none', 'expected_changes': [], 'unexpected_changes': []}


def _is_expected(path):
    # Matches the exact file, a rotated variant (auth.log.1), a file under an
    # allow-listed directory (the systemd journal, /run/sudo), or a login cache file.
    if _is_login_cache(path):
        return True
    return any(path == allowed or path.startswith(allowed + '/') or path.startswith(allowed + '.')
               for allowed in EXPECTED_CHANGES)


def certificate_from_changes(changed_paths, method):
    """Build a certificate from a list of changed paths and the method used.

    ``method`` must be ``docker_diff`` or ``filesystem_hash``; anything else is
    treated as no verification (``not_run``).
    """
    if method not in ('docker_diff', 'filesystem_hash'):
        return not_run()
    paths = list(changed_paths)

    def _is_ancestor_dir(path):
        # docker diff lists a parent directory ('C /run') whenever a child changes;
        # that is directory metadata, not a write, so it inherits the child's verdict.
        prefix = path.rstrip('/') + '/'
        return any(other != path and other.startswith(prefix) for other in paths)

    expected, unexpected = [], []
    for path in paths:
        (expected if _is_expected(path) or _is_ancestor_dir(path) else unexpected).append(path)
    expected = sorted(set(expected))
    unexpected = sorted(set(unexpected))
    status = 'passed' if not unexpected else 'failed'
    return {'status': status, 'method': method, 'expected_changes': expected, 'unexpected_changes': unexpected}


def parse_docker_diff(diff_output):
    """Return changed/added paths from ``docker diff <container>`` output.

    Lines are ``C /path`` (changed), ``A /path`` (added) or ``D /path`` (deleted);
    deletions and additions both count as a write.
    """
    paths = []
    for line in diff_output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] in ('C', 'A', 'D'):
            paths.append(parts[1].strip())
    return paths


def certificate_from_docker_diff(diff_output):
    """Certificate from ``docker diff`` output (host-side verification method)."""
    return certificate_from_changes(parse_docker_diff(diff_output), 'docker_diff')


def _hash_map(text):
    result = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            digest, path = parts
            result[path.strip()] = digest.strip()
    return result


def certificate_from_hashes(before, after):
    """Certificate from two ``sha256sum`` fingerprints (``find | xargs sha256sum``).

    ``before``/``after`` may be either dicts of ``path -> digest`` or raw command
    output. A path counts as changed when its digest differs or it was added/removed.
    """
    before = before if isinstance(before, dict) else _hash_map(before)
    after = after if isinstance(after, dict) else _hash_map(after)
    changed = [path for path in set(before) | set(after) if before.get(path) != after.get(path)]
    return certificate_from_changes(changed, 'filesystem_hash')
