"""Typed collection errors.

Kept separate so parsers and the SSH layer can raise and catch without importing
each other. Collector/CLI map these to clean messages and exit code 2; they never
echo payloads that could contain secrets.
"""


class CollectorError(Exception):
    """Base class for every collection failure."""


class CommandNotAllowed(CollectorError):
    """A command ID outside the frozen allow-list was requested (EC-02)."""


class CommandTimeout(CollectorError):
    """A command exceeded its per-command timeout (EC-16)."""


class CommandFailed(CollectorError):
    """A command returned a non-zero exit status where success was required."""


class NotAuthorised(CollectorError):
    """The operator declined the authorisation prompt (CL-04)."""


class SSHConnectionError(CollectorError):
    """The SSH connection could not be established (EC-01)."""


class AuthenticationError(SSHConnectionError):
    """Authentication was rejected (wrong key or password)."""


class HostKeyError(SSHConnectionError):
    """The host key was unknown or did not match a stored key."""
