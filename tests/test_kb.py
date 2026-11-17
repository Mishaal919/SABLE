"""KB-01..KB-05, KB-02 version comparison, KB-03 rule fixtures and NV-05 tags."""
import shutil
from importlib.resources import files
from pathlib import Path

import pytest

from analysis_helpers import account, capability, credential, cron, package, perm, snapshot, sudo, suid
from sable.graph.build import analyze, build_graph
from sable.kb.loader import ATTACK_TECHNIQUES, KnowledgeBaseError, load_kb
from sable.kb.versions import compare_versions

PACKAGED = Path(str(files('sable.kb').joinpath('data')))


@pytest.fixture(scope='module')
def kb():
    return load_kb()


def rules_fired(snap, kb, **config):
    return {edge['rule'] for edge in build_graph(snap, kb, config)['graph']['edges']}


# KB-01 / KB-04 / KB-05 -------------------------------------------------------

def test_packaged_catalogue_is_valid_and_sized(kb):
    assert 30 <= len(kb['binaries']) <= 45
    assert 15 <= len(kb['cves']) <= 25
    assert {'writable_root_cron', 'readable_credential', 'sudo_nopasswd_gtfobin', 'readable_shadow',
            'writable_service_file'} <= set(kb['rules'])
    assert kb['meta']['version'] and kb['meta']['date']


def test_suid_find_creates_step_and_unlisted_binary_does_not(kb):
    graph = build_graph(snapshot(suid('/usr/bin/find')), kb)['graph']
    assert [(e['src'], e['dst'], e['rule']) for e in graph['edges']] == [('user:auditor', 'root', 'suid_gtfobin')]
    assert build_graph(snapshot(suid('/usr/bin/passwd')), kb)['graph']['edges'] == []


def test_versioned_binary_names_match_catalogue(kb):
    assert rules_fired(snapshot(capability('/usr/bin/python3.10')), kb) == {'setuid_capability'}


def test_new_rule_file_is_used_without_code_change(tmp_path):
    shutil.copytree(PACKAGED, tmp_path / 'data')
    (tmp_path / 'data/extra.yaml').write_text('''
rules:
  - id: readable_backup_key
    kind: match
    description: Readable backup key
    evidence_type: file_permission
    when: [{field: path, op: eq, value: /srv/backup.key}]
    actors: {field: readable_by}
    target: "cred:{path}"
    base: 0.7
    attack: T1552.001
    fix: {type: chmod, description: "Restrict {path}", command: "chmod 600 {path}", rollback: "chmod {mode} {path}"}
''', encoding='utf-8')
    kb = load_kb(tmp_path / 'data')
    assert rules_fired(snapshot(perm('/srv/backup.key', readable_by=['auditor'])), kb) == {'readable_backup_key'}


@pytest.mark.parametrize('content,expected', [
    ('rules:\n  - id: broken\n    kind: match\n', 'broken.yaml: rules/0'),
    ('binaries:\n  - {name: find, contexts: [teleport], result: root, note: x}\n', 'broken.yaml: binaries/0/contexts/0'),
    ('rules: [\n', 'broken.yaml: line'),
    ('cves:\n  - id: CVE-2099-0001\n    name: x\n    package: sudo\n    note: x\n'
     '    cvss: {score: 7.8, vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}\n'
     '    affected: [{distro: ubuntu 22.04, fixed: "not a version"}]\n', 'broken.yaml: cves/0/affected/0/fixed'),
])
def test_malformed_file_names_file_and_field(tmp_path, content, expected):
    shutil.copytree(PACKAGED, tmp_path / 'data')
    (tmp_path / 'data/broken.yaml').write_text(content, encoding='utf-8')
    with pytest.raises(KnowledgeBaseError, match=expected):
        load_kb(tmp_path / 'data')


def test_duplicate_rule_and_missing_rollback_are_rejected(tmp_path):
    shutil.copytree(PACKAGED, tmp_path / 'data')
    (tmp_path / 'data/dupe.yaml').write_text((PACKAGED / 'rules.yaml').read_text(encoding='utf-8'), encoding='utf-8')
    with pytest.raises(KnowledgeBaseError, match='duplicate'):
        load_kb(tmp_path / 'data')
    (tmp_path / 'data/dupe.yaml').unlink()
    rules = tmp_path / 'data/rules.yaml'
    rules.write_text(rules.read_text(encoding='utf-8').replace('      rollback: "chmod {mode} {path}"\n', '', 1), encoding='utf-8')
    with pytest.raises(KnowledgeBaseError, match='rules.yaml: rules/0/fix'):
        load_kb(tmp_path / 'data')


def test_catalogue_version_reaches_results(kb):
    results = analyze(snapshot(), kb=kb)
    assert results['meta']['kb_version'] == kb['meta']['version']
    assert results['meta']['kb_date'] == kb['meta']['date']


# KB-02 -----------------------------------------------------------------------

@pytest.mark.parametrize('left,right,expected', [
    ('1.0', '1.0', 0),
    ('1.0-1', '1.0', 1),
    ('1.0~rc1', '1.0', -1),
    ('1.0~rc1-1', '1.0~rc2-1', -1),
    ('2:1.0', '1:9.9', 1),
    ('1.10', '1.9', 1),
    ('1.0.0', '1.0', 1),
    ('0.105-26ubuntu1.1', '0.105-26ubuntu1.2', -1),
    ('0.105-33', '0.105-26ubuntu1.2', 1),
    ('1.8.31-1ubuntu1.2', '1.8.31-1ubuntu1', 1),
    ('1.8.21p2-3ubuntu1.4', '1.8.21p2-3ubuntu1.1', 1),
    ('1.9.9-1ubuntu2.1', '1.9.9-1ubuntu2.2', -1),
    ('2.35-0ubuntu3.4', '2.35-0ubuntu3.10', -1),
    ('2.36-9+deb12u3', '2.36-9+deb12u2', 1),
    ('5.15.0-91.101', '5.15.0-70.77', 1),
    ('5.13.0-30.33~20.04.1', '5.13.0-35.40~20.04.1', -1),
    ('5.13.0-35.40~20.04.1', '5.13.0-35.40', -1),
    ('5.4.0-100.113', '5.8', -1),
    ('1.0+dfsg-1', '1.0-1', 1),
    ('1.0a', '1.0+', -1),
])
def test_debian_version_comparison(left, right, expected):
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


@pytest.mark.parametrize('bad', ['', 'abc', 'x:1.0', '1.0 beta'])
def test_invalid_versions_are_rejected(bad):
    with pytest.raises(ValueError):
        compare_versions(bad, '1.0')


def test_vulnerable_polkit_creates_inferred_cvss_step(kb):
    edges = build_graph(snapshot(package('policykit-1', '0.105-26ubuntu1.1'), distro='ubuntu 20.04'), kb)['graph']['edges']
    pwnkit = [e for e in edges if e['rule'] == 'CVE-2021-4034']
    assert len(pwnkit) == 1
    assert pwnkit[0]['breakdown'] == {'base': 0.78, 'strength': 'inferred', 'factor': 0.6}
    assert pwnkit[0]['likelihood'] == pytest.approx(0.468)
    assert pwnkit[0]['attack'] == 'T1068'


def test_fixed_polkit_and_other_distros_do_not_match(kb):
    assert rules_fired(snapshot(package('policykit-1', '0.105-26ubuntu1.2'), distro='ubuntu 20.04'), kb) == set()
    assert rules_fired(snapshot(package('policykit-1', '0.105-26ubuntu1.1'), distro='ubuntu 24.04'), kb) == set()


def test_kernel_cve_uses_running_kernel_package_and_introduced_bound(kb):
    vulnerable = snapshot(package('linux-image-5.13.0-30-generic', '5.13.0-30.33~20.04.1'),
                          distro='ubuntu 20.04', kernel='5.13.0-30-generic')
    assert 'CVE-2022-0847' in rules_fired(vulnerable, kb)
    older = snapshot(package('linux-image-5.4.0-100-generic', '5.4.0-100.113'), distro='ubuntu 20.04', kernel='5.4.0-100-generic')
    assert 'CVE-2022-0847' not in rules_fired(older, kb)
    not_running = snapshot(package('linux-image-5.13.0-30-generic', '5.13.0-30.33~20.04.1'), distro='ubuntu 20.04', kernel='5.15.0-1-generic')
    assert 'CVE-2022-0847' not in rules_fired(not_running, kb)


def test_cve_fix_template_names_fixed_version(kb):
    results = analyze(snapshot(package('policykit-1', '0.105-26ubuntu1.1'), distro='ubuntu 20.04'), kb=kb)
    fix = next(f for f in results['fix_candidates'] if 'CVE-2021-4034' in f['description'])
    assert fix['type'] == 'manual' and fix['execution'] == 'recommend_only'
    assert '0.105-26ubuntu1.2' in fix['command'] and fix['rollback'] == 'apt-get install policykit-1=0.105-26ubuntu1.1'


# KB-03: one positive and one negative fixture per rule -----------------------

RULE_CASES = {
    'suid_gtfobin': ([suid('/usr/bin/find')], [suid('/usr/bin/find', owner='bob')], {}),
    'sudo_nopasswd_gtfobin': ([sudo(commands=['/usr/bin/vim'])], [sudo(commands=['/usr/bin/apt-get'])], {}),
    'sudo_password_gtfobin': ([sudo(commands=['ALL'], nopasswd=False)], [sudo(commands=['/usr/bin/id'], nopasswd=False)], {}),
    'setuid_capability': ([capability('/usr/bin/perl')], [capability('/usr/bin/perl', ['cap_net_raw+ep'])], {}),
    'writable_root_cron': ([cron()], [cron(run_as='backup')], {}),
    'readable_credential': ([credential()], [credential(readable_by=['www-data'])], {}),
    'readable_shadow': ([perm('/etc/shadow', readable_by=['auditor'])], [perm('/etc/passwd', readable_by=['auditor'])], {}),
    'readable_private_key': ([perm('/home/bob/.ssh/id_rsa', readable_by=['auditor'])], [perm('/home/bob/.ssh/id_rsa.pub', readable_by=['auditor'])], {}),
    'writable_account_file': ([perm('/etc/passwd', writable_by=['auditor'])], [perm('/etc/hosts', writable_by=['auditor'])], {}),
    'writable_sudoers': ([perm('/etc/sudoers.d/90-ops', writable_by=['auditor'])], [perm('/etc/sudoers.d/90-ops', writable_by=['root'])], {}),
    'writable_cron_config': ([perm('/etc/crontab', writable_by=['auditor'])], [perm('/etc/crontab', readable_by=['auditor'])], {}),
    'writable_service_file': ([perm('/etc/systemd/system/app.service', writable_by=['auditor'])], [perm('/etc/systemd/system/app.conf', writable_by=['auditor'])], {}),
    'credential_reuse': ([credential(), account('dbadmin')], [credential(), account('dbadmin', shell='/usr/sbin/nologin')], {}),
    'unknown_sudo': ([credential(), account('dbadmin')], [credential(), account('dbadmin'), sudo(user='dbadmin', commands=['/usr/bin/id'])], {'missing': True}),
    'vulnerable_package': ([package('sudo', '1.9.9-1ubuntu2.1')], [package('sudo', '1.9.9-1ubuntu2.2')], {}),
}


def test_every_rule_has_a_case(kb):
    assert set(RULE_CASES) == set(kb['rules'])


@pytest.mark.parametrize('rule_id', sorted(RULE_CASES))
def test_rule_positive_and_negative(kb, rule_id):
    positive, negative, options = RULE_CASES[rule_id]
    missing = [{'check': 'sudoers_full', 'reason': 'permission_denied'}] if options.get('missing') else []
    if rule_id == 'vulnerable_package':
        fired = lambda ev: any(r.startswith('CVE-') for r in rules_fired(snapshot(*ev, missing=missing), kb))
    else:
        fired = lambda ev: rule_id in rules_fired(snapshot(*ev, missing=missing), kb)
    assert fired(positive)
    assert not fired(negative)


def test_unknown_sudo_needs_the_missing_check(kb):
    assert 'unknown_sudo' not in rules_fired(snapshot(credential(), account('dbadmin')), kb)


# NV-05 / RP-05 ---------------------------------------------------------------

def test_every_rule_has_valid_attack_id_and_rollback(kb):
    for rule in kb['rules'].values():
        assert rule['attack'] in ATTACK_TECHNIQUES
        assert rule['fix']['rollback'].strip()


def test_attack_ids_appear_on_every_generated_step(kb):
    results = analyze(snapshot(suid('/usr/bin/find'), cron(), credential(), perm('/etc/shadow', readable_by=['auditor'])), kb=kb)
    assert results['graph']['edges']
    assert all(edge['attack'] in ATTACK_TECHNIQUES for edge in results['graph']['edges'])
