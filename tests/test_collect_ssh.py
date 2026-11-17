"""EC-01: SSH connection, host-key policy and clean auth errors (mocked paramiko)."""
import types

import pytest

from sable.collect import ssh
from sable.collect.errors import AuthenticationError, HostKeyError, SSHConnectionError


def make_paramiko(raise_with=None):
    """Return a fake paramiko namespace and a dict recording client interactions."""
    recorded = {}
    exceptions = {
        'AuthenticationException': type('AuthenticationException', (Exception,), {}),
        'BadHostKeyException': type('BadHostKeyException', (Exception,), {}),
        'SSHException': type('SSHException', (Exception,), {}),
    }

    class SSHClient:
        def load_system_host_keys(self):
            recorded['system'] = True

        def load_host_keys(self, path):
            recorded['known_hosts'] = path

        def set_missing_host_key_policy(self, policy):
            recorded['policy'] = policy

        def connect(self, **kwargs):
            recorded['connect'] = kwargs
            if raise_with:
                raise raise_with(exceptions)

        def close(self):
            recorded['closed'] = True

    namespace = types.SimpleNamespace(
        SSHClient=SSHClient,
        RejectPolicy=type('RejectPolicy', (), {}),
        AutoAddPolicy=type('AutoAddPolicy', (), {}),
        **exceptions,
    )
    return namespace, recorded


def test_default_policy_rejects_unknown_hosts():
    paramiko, recorded = make_paramiko()
    ssh.connect('h', 'auditor', password='pw', paramiko_module=paramiko)
    assert isinstance(recorded['policy'], paramiko.RejectPolicy)


def test_accept_new_host_key_uses_autoadd():
    paramiko, recorded = make_paramiko()
    ssh.connect('h', 'auditor', password='pw', accept_new_host_key=True, paramiko_module=paramiko)
    assert isinstance(recorded['policy'], paramiko.AutoAddPolicy)


def test_wrong_password_raises_clean_authentication_error():
    paramiko, _ = make_paramiko(raise_with=lambda exc: exc['AuthenticationException']('bad'))
    with pytest.raises(AuthenticationError) as info:
        ssh.connect('h', 'auditor', password='hunter2', paramiko_module=paramiko)
    assert 'hunter2' not in str(info.value)  # password never echoed


def test_unknown_host_key_is_refused():
    paramiko, _ = make_paramiko(
        raise_with=lambda exc: exc['SSHException']('Server h not found in known_hosts'))
    with pytest.raises(HostKeyError):
        ssh.connect('h', 'auditor', password='pw', paramiko_module=paramiko)


def test_bad_host_key_raises_host_key_error():
    paramiko, _ = make_paramiko(raise_with=lambda exc: exc['BadHostKeyException']('mismatch'))
    with pytest.raises(HostKeyError):
        ssh.connect('h', 'auditor', password='pw', paramiko_module=paramiko)


def test_network_failure_raises_connection_error():
    paramiko, _ = make_paramiko(raise_with=lambda exc: OSError('no route'))
    with pytest.raises(SSHConnectionError):
        ssh.connect('h', 'auditor', password='pw', paramiko_module=paramiko)
