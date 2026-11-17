"""NV-02 / NF-01: no-writes certificate."""
from sable.collect.certificate import (
    certificate_from_changes,
    certificate_from_docker_diff,
    certificate_from_hashes,
    not_run,
)
from sable.contracts.validation import validate


def _snapshot(certificate):
    return {
        'schema_version': '1.0',
        'meta': {'host': 'h', 'distro': 'ubuntu 22.04', 'kernel': 'k', 'user': 'u',
                 'groups': ['u'], 'mode': 'unprivileged', 'timestamp': '2026-11-17T00:00:00Z',
                 'sable_version': '0.1.0'},
        'evidence': [], 'missing': [], 'no_writes': certificate,
    }


def test_not_run_is_honest_default():
    cert = not_run()
    assert cert['status'] == 'not_run' and cert['method'] == 'none'
    validate(_snapshot(cert), 'snapshot')


def test_only_allowlisted_log_changes_pass():
    diff = 'C /var/log/auth.log\nC /var/log/wtmp\nC /run/utmp\n'
    cert = certificate_from_docker_diff(diff)
    assert cert['status'] == 'passed'
    assert cert['method'] == 'docker_diff'
    assert cert['unexpected_changes'] == []
    validate(_snapshot(cert), 'snapshot')


def test_unexpected_write_is_flagged():
    diff = 'C /var/log/auth.log\nA /opt/backdoor\nC /etc/passwd\n'
    cert = certificate_from_docker_diff(diff)
    assert cert['status'] == 'failed'
    assert '/opt/backdoor' in cert['unexpected_changes']
    assert '/etc/passwd' in cert['unexpected_changes']
    assert '/var/log/auth.log' in cert['expected_changes']


def test_rotated_log_variant_is_expected():
    cert = certificate_from_changes(['/var/log/auth.log.1'], 'filesystem_hash')
    assert cert['status'] == 'passed'


def test_hash_fingerprint_detects_change():
    before = {'/etc/passwd': 'aaa', '/var/log/wtmp': 'bbb'}
    after = {'/etc/passwd': 'ZZZ', '/var/log/wtmp': 'ccc'}
    cert = certificate_from_hashes(before, after)
    assert cert['status'] == 'failed'
    assert '/etc/passwd' in cert['unexpected_changes']
    assert '/var/log/wtmp' in cert['expected_changes']


def test_hash_fingerprint_clean_run_passes():
    text_before = 'aaa  /etc/passwd\nbbb  /var/log/wtmp\n'
    text_after = 'aaa  /etc/passwd\nccc  /var/log/wtmp\n'
    cert = certificate_from_hashes(text_before, text_after)
    assert cert['status'] == 'passed'
    assert cert['unexpected_changes'] == []


def test_unknown_method_is_not_run():
    assert certificate_from_changes(['/x'], 'none')['status'] == 'not_run'
