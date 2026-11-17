"""Small synthetic snapshot builders shared by the analysis tests."""
import copy
import json
from pathlib import Path

FIXTURES = Path(__file__).parent / 'fixtures'


def fixture_snapshot(name):
    return json.loads((FIXTURES / f'snapshots/{name}.json').read_text(encoding='utf-8'))


def snapshot(*evidence, missing=(), **meta):
    """A valid snapshot based on the hardened fixture with the given evidence."""
    base = fixture_snapshot('hardened')
    base['meta'].update(meta)
    base['evidence'] = [{'id': f'ev-{i:02d}', 'source_cmd': 'test', 'strength': 'observed', **copy.deepcopy(item)}
                        for i, item in enumerate(evidence, 1)]
    base['missing'] = [dict(item) for item in missing]
    return base


def suid(path, owner='root', mode='4755', is_suid=True):
    return {'type': 'suid_binary', 'data': {'path': path, 'owner': owner, 'group': owner, 'mode': mode, 'suid': is_suid, 'sgid': False}}


def perm(path, mode='644', readable_by=(), writable_by=()):
    return {'type': 'file_permission', 'data': {'path': path, 'owner': 'root', 'group': 'root', 'mode': mode,
                                                'readable_by': list(readable_by), 'writable_by': list(writable_by)}}


def sudo(user='auditor', commands=('/usr/bin/find',), nopasswd=True, runas='root'):
    return {'type': 'sudo_rule', 'data': {'user': user, 'runas': runas, 'nopasswd': nopasswd, 'commands': list(commands)}}


def capability(path, caps=('cap_setuid+ep',)):
    return {'type': 'capability', 'data': {'path': path, 'capabilities': list(caps)}}


def cron(run_as='root', writable_by=('auditor',), path='/opt/backup.sh'):
    return {'type': 'scheduled_job', 'data': {'scheduler': 'cron', 'run_as': run_as, 'script_path': path, 'script_owner': 'root',
                                              'script_group': 'root', 'script_mode': '777', 'writable_by': list(writable_by)}}


def credential(path='/var/www/config.php', readable_by=('auditor',), pattern='password'):
    return {'type': 'credential_location', 'data': {'path': path, 'line': 4, 'pattern_type': pattern, 'readable_by': list(readable_by)}}


def account(name, uid=1001, shell='/bin/bash'):
    return {'type': 'user_account', 'data': {'name': name, 'uid': uid, 'gid': uid, 'groups': [name], 'home': f'/home/{name}', 'shell': shell}}


def package(name, version):
    return {'type': 'package', 'data': {'name': name, 'version': version, 'architecture': 'amd64'}}


def service(name, address='0.0.0.0', port=80, running=True):
    return {'type': 'service', 'data': {'name': name, 'package': name, 'version': '1.0', 'running': running,
                                        'listeners': [{'address': address, 'port': port, 'protocol': 'tcp'}]}}


def strength(item, value):
    return {**item, 'strength': value}
