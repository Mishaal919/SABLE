"""EC-02: the read-only command allow-list and the only gateway to the SSH channel.

A caller can only ask for a command by **ID**. :meth:`CommandRunner.run` is the one
function in the whole codebase that calls ``exec_command`` (a CI test enforces this).
Every command is a fixed, read-only template; the only variable parts are named
``{placeholders}`` whose values are validated against a strict character set and
shell-quoted, so nothing a caller passes can change the shape of a command or add a
second command. Unknown IDs raise :class:`CommandNotAllowed`.

``CANONICAL_SOURCES`` lists the command IDs that may appear as an evidence
``source_cmd`` (the contract in docs/CONTRACTS.md). Other entries are read-only
helpers (per-file ``stat``, file reads, fingerprinting) that support a check but are
never written into evidence.
"""
import re
import shlex
import socket
import string
import time

from sable.collect.audit import AuditLog
from sable.collect.errors import CommandNotAllowed, CommandTimeout

# Values substituted into a template must match this. Combined with shlex.quote this
# makes command injection impossible: quotes, $, ;, |, &, <, >, (, ), backticks,
# newlines and other shell metacharacters are rejected. A plain space is allowed
# (real file paths contain them) and is neutralised by shlex.quote.
_SAFE_VALUE = re.compile(r'^[A-Za-z0-9 _@%+=:,./~^-]+$')

# The frozen registry. Keys are command IDs; values are fixed command strings with
# optional simple {named} placeholders. Never add a template that embeds raw caller
# input outside a placeholder, and never add a write/mutate command here.
ALLOWLIST = {
    # --- identity and inventory -------------------------------------------------
    'system_identity': "cat /etc/os-release; echo '##SABLE##'; uname -r; echo '##SABLE##'; uname -m; echo '##SABLE##'; id",
    'installed_packages': "dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n'",
    'user_accounts': 'getent passwd',
    'groups': 'getent group',
    # --- privilege-relevant filesystem state ------------------------------------
    'suid_find': "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -printf '%m\\t%u\\t%g\\t%p\\n' 2>/dev/null",
    'sensitive_permissions': "stat -c '%a\\t%U\\t%G\\t%n' /etc/shadow /etc/gshadow /etc/passwd /etc/group /etc/sudoers /root 2>/dev/null",
    'world_writable': "find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -not -path '/tmp/*' -printf '%m\\t%u\\t%g\\t%p\\n' 2>/dev/null",
    'file_capabilities': 'getcap -r / 2>/dev/null',
    'stat_paths': "stat -c '%a\\t%U\\t%G\\t%n' {paths} 2>/dev/null",
    # --- sudo -------------------------------------------------------------------
    'sudo_rules': 'sudo -n -l 2>/dev/null',
    'sudoers_full': 'sudo -n cat /etc/sudoers 2>/dev/null',
    # --- scheduled jobs ---------------------------------------------------------
    'scheduled_jobs': "cat /etc/crontab 2>/dev/null; echo '##SABLE##'; for f in /etc/cron.d/*; do echo \"#file $f\"; cat \"$f\"; done 2>/dev/null; echo '##SABLE##'; crontab -l 2>/dev/null; echo '##SABLE##'; systemctl list-timers --all --no-legend 2>/dev/null",
    # --- services ---------------------------------------------------------------
    'services': "ss -tulpnH 2>/dev/null; echo '##SABLE##'; systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null",
    'package_of_file': 'dpkg-query -S {path} 2>/dev/null',
    # --- credentials ------------------------------------------------------------
    'credential_find': "find /var/www /etc /home /opt /srv -maxdepth 6 -type f \\( -name '*.conf' -o -name '*.cnf' -o -name '*.env' -o -name '*.ini' -o -name '*.yaml' -o -name '*.yml' -o -name '*.php' -o -name '*.json' \\) -size -1048576 2>/dev/null",
    'read_file': 'head -c 1048576 {path} 2>/dev/null',
    # --- accounts and ssh -------------------------------------------------------
    'ssh_effective_config': 'sshd -T 2>/dev/null',
    'ssh_config_file': 'cat /etc/ssh/sshd_config 2>/dev/null',
    # --- no-writes fingerprint (NV-02) ------------------------------------------
    'fs_fingerprint': "find / -xdev -type f -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -printf '%p\\n' 2>/dev/null | sort | xargs -r -d '\\n' sha256sum 2>/dev/null",
}

# Command IDs allowed to appear as an evidence `source_cmd` (CONTRACTS.md).
CANONICAL_SOURCES = frozenset({
    'system_identity', 'suid_find', 'sensitive_permissions', 'sudo_rules', 'sudoers_full',
    'scheduled_jobs', 'services', 'file_capabilities', 'credential_scan', 'user_accounts',
    'ssh_settings', 'installed_packages',
})


def _quote(value):
    if isinstance(value, (list, tuple)):
        return ' '.join(_quote(item) for item in value)
    text = str(value)
    if not _SAFE_VALUE.match(text):
        raise CommandNotAllowed(f'unsafe command argument: {text!r}')
    return shlex.quote(text)


def render(command_id, params=None):
    """Return the exact command string for an allow-listed ID (no execution)."""
    if command_id not in ALLOWLIST:
        raise CommandNotAllowed(f'command not in allow-list: {command_id!r}')
    template = ALLOWLIST[command_id]
    params = params or {}
    needed = {name for _, name, _, _ in string.Formatter().parse(template) if name}
    extra = set(params) - needed
    if extra:
        raise CommandNotAllowed(f'command {command_id!r} does not accept {sorted(extra)}')
    missing = needed - set(params)
    if missing:
        raise CommandNotAllowed(f'command {command_id!r} is missing {sorted(missing)}')
    quoted = {name: _quote(params[name]) for name in needed}
    return template.format(**quoted)


class CommandResult:
    """Result of one allow-listed command run."""

    __slots__ = ('command_id', 'command', 'stdout', 'stderr', 'exit_status', 'duration')

    def __init__(self, command_id, command, stdout, stderr, exit_status, duration):
        self.command_id = command_id
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.exit_status = exit_status
        self.duration = duration

    @property
    def ok(self):
        return self.exit_status == 0


class CommandRunner:
    """Runs allow-listed commands over an SSH channel and audits every one.

    ``client`` is any object exposing ``exec_command(command, timeout=...)`` and
    returning ``(stdin, stdout, stderr)`` file-like objects, i.e. a connected
    ``paramiko.SSHClient`` in production or a fake in tests. This class is the single
    place that calls ``exec_command``.
    """

    def __init__(self, client, audit, timeout=30):
        self.client = client
        self.audit = audit
        self.timeout = timeout

    def run(self, command_id, **params):
        command = render(command_id, params)
        start = time.monotonic()
        try:
            _stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            exit_status = stdout.channel.recv_exit_status()
        except socket.timeout as exc:
            self.audit.record(command_id, command, 'timeout', time.monotonic() - start)
            raise CommandTimeout(f'command {command_id!r} timed out') from exc
        duration = time.monotonic() - start
        self.audit.record(command_id, command, exit_status, duration)
        return CommandResult(command_id, command, _text(out), _text(err), exit_status, duration)


def _text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return value


def open_audit_log(path, secrets=()):
    """Convenience: an :class:`AuditLog` writing to ``path``."""
    return AuditLog(path, secrets)
