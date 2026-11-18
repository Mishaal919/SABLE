"""CL-04 authorisation and CL-05 credential-handling safety."""
import pytest

from sable.collect.authorize import confirm_authorisation
from sable.collect.collector import collect_snapshot
from sable.collect.errors import NotAuthorised


def test_authorisation_prompt_yes():
    assert confirm_authorisation(prompt=lambda _p: 'y') is True
    assert confirm_authorisation(prompt=lambda _p: 'yes') is True


def test_authorisation_prompt_no():
    assert confirm_authorisation(prompt=lambda _p: 'n') is False
    assert confirm_authorisation(prompt=lambda _p: '') is False


def test_assume_yes_skips_prompt():
    def explode(_p):
        raise AssertionError('prompt must not be shown with assume_yes')
    assert confirm_authorisation(assume_yes=True, prompt=explode) is True


def test_declined_authorisation_opens_no_connection(monkeypatch):
    """Answering 'n' must stop before any SSH client is constructed (CL-04)."""
    import sable.collect.ssh as ssh_module

    def fail_connect(*args, **kwargs):
        raise AssertionError('ssh.connect must not be called when authorisation is declined')

    monkeypatch.setattr(ssh_module, 'connect', fail_connect)
    with pytest.raises(NotAuthorised):
        collect_snapshot('h', 'auditor', password='pw', prompt=lambda _p: 'n')


def test_eof_declines():
    def eof(_p):
        raise EOFError
    assert confirm_authorisation(prompt=eof) is False
