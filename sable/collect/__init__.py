"""SABLE read-only evidence collection (Mishaal).

Public surface:

- :func:`collect_snapshot` - live: authorise, connect over SSH, return a snapshot.
- :func:`run_collection` / :func:`assemble_snapshot` - the pure pipeline over a
  :class:`CommandRunner`, used by tests and offline tooling.
- :class:`CommandRunner`, :data:`ALLOWLIST` - the read-only command gateway (EC-02).
- :mod:`sable.collect.certificate` - the NV-02 no-writes certificate.

Safety invariants: only allow-listed read-only commands run; every command is
audited (CL-03); credentials are redacted at the source (EC-10/CL-05); nothing is
ever written to the target.
"""
from sable.collect.allowlist import ALLOWLIST, CANONICAL_SOURCES, CommandResult, CommandRunner
from sable.collect.collector import assemble_snapshot, collect_snapshot, run_collection
from sable.collect.errors import (
    AuthenticationError,
    CollectorError,
    CommandNotAllowed,
    CommandTimeout,
    HostKeyError,
    NotAuthorised,
    SSHConnectionError,
)

__all__ = [
    'ALLOWLIST',
    'CANONICAL_SOURCES',
    'CommandResult',
    'CommandRunner',
    'collect_snapshot',
    'run_collection',
    'assemble_snapshot',
    'CollectorError',
    'CommandNotAllowed',
    'CommandTimeout',
    'NotAuthorised',
    'SSHConnectionError',
    'AuthenticationError',
    'HostKeyError',
]
