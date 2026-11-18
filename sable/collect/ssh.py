"""EC-01: one SSH connection per run, with host-key verification and timeouts.

paramiko is an optional (``app`` extra) dependency, imported lazily so the rest of
the collector — and its unit tests — load without it. ``connect`` only opens the
session and returns the client; running commands stays in
:mod:`sable.collect.allowlist` (the single command gateway). A ``paramiko_module``
argument lets tests inject a fake paramiko with fake exception classes and client.
"""
import os
import socket

from sable.collect.errors import AuthenticationError, HostKeyError, SSHConnectionError


def _import_paramiko():
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - exercised only without the app extra
        raise SSHConnectionError('paramiko is not installed; install the "app" extra') from exc
    return paramiko


def host_key_policy(paramiko, accept_new_host_key):
    """RejectPolicy by default (EC-01); AutoAddPolicy for trust-on-first-use."""
    return paramiko.AutoAddPolicy() if accept_new_host_key else paramiko.RejectPolicy()


def connect(host, user, *, port=22, key_path=None, password=None,
            accept_new_host_key=False, timeout=30, paramiko_module=None):
    """Open and return one authenticated SSH client.

    Host-key checking is on by default; an unknown key is refused unless
    ``accept_new_host_key`` is set. Maps paramiko failures to typed collector errors
    with clean messages (no password is ever echoed).
    """
    paramiko = paramiko_module or _import_paramiko()
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    known_hosts = os.path.expanduser('~/.ssh/known_hosts')
    if os.path.exists(known_hosts):
        try:
            client.load_host_keys(known_hosts)
        except OSError:
            pass
    client.set_missing_host_key_policy(host_key_policy(paramiko, accept_new_host_key))
    try:
        client.connect(
            hostname=host, port=port, username=user,
            key_filename=key_path, password=password, timeout=timeout,
            allow_agent=False, look_for_keys=(key_path is None and password is None),
        )
    except paramiko.AuthenticationException as exc:
        raise AuthenticationError('authentication failed') from exc
    except paramiko.BadHostKeyException as exc:
        raise HostKeyError('host key does not match the stored key') from exc
    except paramiko.SSHException as exc:
        message = str(exc).lower()
        if 'known_hosts' in message or 'host key' in message or 'not found' in message:
            raise HostKeyError('unknown host key; use --accept-new-host-key to trust it') from exc
        raise SSHConnectionError('SSH connection failed') from exc
    except (socket.timeout, socket.error, OSError) as exc:
        raise SSHConnectionError('could not reach the host') from exc
    return client


def close(client):
    """Close a client, ignoring errors (best-effort cleanup)."""
    try:
        client.close()
    except Exception:
        pass
