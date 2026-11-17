"""EC-13/EC-14/EC-16/NF-05/CL-05: collector orchestration over a fake runner."""
import json

from sable.collect.allowlist import CommandResult
from sable.collect.collector import assemble_snapshot, run_collection
from sable.collect.errors import CommandTimeout
from sable.contracts.validation import validate
from sable.graph.build import analyze

PASSWD = (
    'root:x:0:0:root:/root:/bin/bash\n'
    'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n'
    'auditor:x:1000:1000::/home/auditor:/bin/bash\n'
    'dbadmin:x:1001:1001::/home/dbadmin:/bin/bash\n'
)
GROUP = 'root:x:0:\nwww-data:x:33:\nauditor:x:1000:\ndbadmin:x:1001:\n'
SECRET = 'S3cr3t-LAB-ONLY'


def _outputs():
    return {
        'system_identity': ('ID=ubuntu\nVERSION_ID="22.04"\n##SABLE##\n5.15.0-generic\n'
                            '##SABLE##\nx86_64\n##SABLE##\n'
                            'uid=1000(auditor) gid=1000(auditor) groups=1000(auditor)\n'),
        'user_accounts': PASSWD,
        'groups': GROUP,
        'ssh_effective_config': 'permitrootlogin no\n',
        'suid_find': '',
        'sensitive_permissions': '',
        'world_writable': '',
        'file_capabilities': '',
        'installed_packages': 'bash\t5.1-6ubuntu1\tamd64\n',
        'services': 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n##SABLE##\n',
        'scheduled_jobs': '##SABLE##\n##SABLE##\n##SABLE##\n',
        'credential_find': '/var/www/config.php\n',
        'stat_paths': lambda paths=None: '644\troot\troot\t/var/www/config.php\n',
        'read_file': lambda path=None: f'db_password = "{SECRET}"\n' if 'config.php' in (path or '') else '',
        'sudo_rules': '',
    }


class FakeRunner:
    def __init__(self, outputs, exits=None, timeouts=()):
        self.outputs = outputs
        self.exits = exits or {}
        self.timeouts = set(timeouts)
        self.calls = []

    def run(self, command_id, **params):
        self.calls.append(command_id)
        if command_id in self.timeouts:
            raise CommandTimeout(command_id)
        value = self.outputs.get(command_id, '')
        if callable(value):
            value = value(**params)
        return CommandResult(command_id, command_id, value, '', self.exits.get(command_id, 0), 0.0)


def _snapshot(config=None, timeouts=()):
    runner = FakeRunner(_outputs(), exits={'sudo_rules': 1}, timeouts=timeouts)
    meta, evidence, missing = run_collection(runner, config or {})
    return assemble_snapshot('weak1.example.test', meta, evidence, missing,
                             'elevated' if (config or {}).get('elevated') else 'unprivileged',
                             secrets=(SECRET,), timestamp='2026-11-17T00:00:00Z')


def test_collected_snapshot_is_valid():
    snapshot = _snapshot()
    validate(snapshot, 'snapshot')
    assert snapshot['meta']['user'] == 'auditor'
    types = {e['type'] for e in snapshot['evidence']}
    assert {'user_account', 'credential_location', 'ssh_setting', 'package', 'service'} <= types


def test_unprivileged_scan_records_sudoers_missing():
    snapshot = _snapshot()
    assert any(m['check'] == 'sudoers_full' and m['reason'] == 'permission_denied'
               for m in snapshot['missing'])


def test_evidence_ids_are_unique_and_ordered():
    snapshot = _snapshot()
    ids = [e['id'] for e in snapshot['evidence']]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    assert ids[0].startswith('ev-')


def test_collection_is_deterministic():
    first = _snapshot()
    second = _snapshot()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_secret_value_never_appears_in_snapshot():
    snapshot = _snapshot()
    assert SECRET not in json.dumps(snapshot)
    cred = [e for e in snapshot['evidence'] if e['type'] == 'credential_location']
    assert cred and cred[0]['data']['pattern_type'] == 'password'
    assert 'auditor' in cred[0]['data']['readable_by']


def test_timeout_records_missing_and_continues():
    snapshot = _snapshot(timeouts=('suid_find',))
    validate(snapshot, 'snapshot')
    assert any(m['check'] == 'suid_find' and m['reason'] == 'timeout' for m in snapshot['missing'])


def test_source_cmds_are_canonical():
    from sable.collect.allowlist import CANONICAL_SOURCES
    snapshot = _snapshot()
    assert all(e['source_cmd'] in CANONICAL_SOURCES for e in snapshot['evidence'])


def test_collected_snapshot_drives_analyzer_chain():
    """EC-13 -> analysis: the collector's weak1-style output yields the dbadmin chain."""
    snapshot = _snapshot()
    results = analyze(snapshot, {'extra_entry_points': [], 'asset_goals': []})
    assert any(p['goal'] == 'root' for p in results['paths'])
    assert any(u['resolving_check'] == 'sudoers_full' for u in results['unknowns'])
