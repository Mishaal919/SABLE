"""EC-02 / CL-03: allow-list gateway and audit log."""
import pathlib
import socket

import pytest

from sable.collect import allowlist
from sable.collect.allowlist import ALLOWLIST, CANONICAL_SOURCES, CommandRunner, render
from sable.collect.audit import MemoryAuditLog, format_line
from sable.collect.errors import CommandNotAllowed, CommandTimeout


class FakeStream:
    def __init__(self, data=b'', exit_status=0):
        self._data = data
        self.channel = type('Chan', (), {'recv_exit_status': lambda self: exit_status})()

    def read(self):
        return self._data


class FakeClient:
    def __init__(self, stdout=b'out', stderr=b'', exit_status=0, raise_timeout=False):
        self.calls = []
        self._stdout = stdout
        self._stderr = stderr
        self._exit = exit_status
        self._raise_timeout = raise_timeout

    def exec_command(self, command, timeout=None):
        self.calls.append((command, timeout))
        if self._raise_timeout:
            raise socket.timeout('slow')
        return None, FakeStream(self._stdout, self._exit), FakeStream(self._stderr, self._exit)


def test_unknown_command_id_is_rejected():
    runner = CommandRunner(FakeClient(), MemoryAuditLog())
    with pytest.raises(CommandNotAllowed):
        runner.run('rm -rf /tmp/x')
    with pytest.raises(CommandNotAllowed):
        runner.run('not_a_real_command')


def test_unsafe_argument_is_rejected():
    with pytest.raises(CommandNotAllowed):
        render('read_file', {'path': '/etc/passwd; rm -rf /'})
    with pytest.raises(CommandNotAllowed):
        render('read_file', {'path': '$(whoami)'})


def test_safe_argument_is_substituted():
    command = render('read_file', {'path': '/var/www/config.php'})
    assert command.startswith('head -c 1048576 ')
    # shlex.quote leaves a shell-safe path unquoted; the point is it is not injectable.
    assert '/var/www/config.php' in command


def test_list_argument_is_substituted_per_item():
    command = render('stat_paths', {'paths': ['/etc/shadow', '/opt/backup.sh']})
    assert '/etc/shadow' in command and '/opt/backup.sh' in command


def test_argument_with_special_chars_is_quoted():
    # A path with a space is valid input and must be shell-quoted, not rejected.
    command = render('read_file', {'path': '/var/www/my app.php'})
    assert "'/var/www/my app.php'" in command


def test_run_executes_once_and_audits():
    client = FakeClient(stdout=b'hello', exit_status=0)
    audit = MemoryAuditLog()
    runner = CommandRunner(client, audit)
    result = runner.run('system_identity')
    assert result.stdout == 'hello'
    assert result.ok
    assert len(client.calls) == 1
    assert len(audit.lines) == 1
    assert 'command_id=system_identity' in audit.lines[0]


def test_timeout_is_audited_and_raised():
    audit = MemoryAuditLog()
    runner = CommandRunner(FakeClient(raise_timeout=True), audit)
    with pytest.raises(CommandTimeout):
        runner.run('suid_find')
    assert len(audit.lines) == 1
    assert 'exit=timeout' in audit.lines[0]


def test_every_audit_line_matches_an_allowlist_entry():
    audit = MemoryAuditLog()
    runner = CommandRunner(FakeClient(), audit)
    for command_id in ('system_identity', 'suid_find', 'sudo_rules'):
        runner.run(command_id)
    for line in audit.lines:
        logged = line.split('command_id=')[1].split('\t')[0]
        assert logged in ALLOWLIST


def test_canonical_sources_are_stable_ids():
    # Every evidence source_cmd tag is a known canonical ID (CONTRACTS.md).
    assert 'credential_scan' in CANONICAL_SOURCES
    assert 'suid_find' in CANONICAL_SOURCES and 'suid_find' in ALLOWLIST


def test_audit_line_redacts_secrets():
    line = format_line('read_file', 'password=hunter2', 0, 0.1, secrets=('hunter2',))
    assert 'hunter2' not in line


def test_exec_command_only_appears_in_allowlist_module():
    """CI check (EC-02): exec_command must be called from one place only."""
    sable_root = pathlib.Path(allowlist.__file__).resolve().parents[1]
    offenders = []
    for path in sable_root.rglob('*.py'):
        if 'exec_command' in path.read_text(encoding='utf-8') and path.name != 'allowlist.py':
            offenders.append(str(path.relative_to(sable_root)))
    assert offenders == [], f'exec_command found outside allowlist.py: {offenders}'
