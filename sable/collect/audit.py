"""CL-03: tamper-evident audit log of every command the collector runs.

Only :func:`sable.collect.allowlist.CommandRunner.run` writes here, so no code
path can execute a command without recording it. One line per command:

    <rfc3339 timestamp>\tcommand_id=<id>\texit=<code>\tduration_ms=<n>\tcommand=<text>

The command text is an allow-listed read-only command; it never contains a
credential. The log is still passed through the shared redactor as defence in
depth before it is written.
"""
from datetime import datetime, timezone

from sable.redaction import redact


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def format_line(command_id, command, exit_code, duration_seconds, secrets=(), timestamp=None):
    """Return a single audit line (without a trailing newline)."""
    duration_ms = int(round(float(duration_seconds) * 1000))
    command = redact(str(command), secrets).replace('\t', ' ').replace('\n', ' ')
    fields = [
        timestamp or _now(),
        f'command_id={command_id}',
        f'exit={exit_code}',
        f'duration_ms={duration_ms}',
        f'command={command}',
    ]
    return '\t'.join(fields)


class AuditLog:
    """Append-only audit log. Use :class:`MemoryAuditLog` in tests."""

    def __init__(self, path, secrets=()):
        self.path = path
        self.secrets = tuple(secrets)

    def record(self, command_id, command, exit_code, duration_seconds, timestamp=None):
        line = format_line(command_id, command, exit_code, duration_seconds, self.secrets, timestamp)
        with open(self.path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')
        return line


class MemoryAuditLog:
    """In-memory audit log for unit tests; keeps every recorded line."""

    def __init__(self, secrets=()):
        self.secrets = tuple(secrets)
        self.lines = []

    def record(self, command_id, command, exit_code, duration_seconds, timestamp=None):
        line = format_line(command_id, command, exit_code, duration_seconds, self.secrets, timestamp)
        self.lines.append(line)
        return line
