"""EC-03..EC-12: evidence parser unit tests (no SSH, hand-made inputs)."""
from sable.collect.checks._util import accessors, group_members
from sable.collect.checks.accounts import parse_accounts, parse_ssh_settings
from sable.collect.checks.capabilities import parse_capabilities
from sable.collect.checks.credentials import credential_evidence, scan_text
from sable.collect.checks.identity import parse_identity
from sable.collect.checks.packages import parse_packages
from sable.collect.checks.permissions import parse_permissions, parse_world_writable
from sable.collect.checks.scheduled import assemble_scheduled, parse_cron
from sable.collect.checks.services import parse_services
from sable.collect.checks.suid import parse_suid
from sable.collect.checks.sudo import parse_sudo_list, parse_sudoers

PASSWD = (
    'root:x:0:0:root:/root:/bin/bash\n'
    'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n'
    'auditor:x:1000:1000::/home/auditor:/bin/bash\n'
)
GROUP = 'root:x:0:\nwww-data:x:33:\nauditor:x:1000:\nsudo:x:27:auditor\n'


def _accounts():
    accounts = parse_accounts(PASSWD, GROUP)
    return accounts, group_members(accounts)


# --- EC-03 identity ---------------------------------------------------------
def test_parse_identity():
    output = ('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n##SABLE##\n'
              '5.15.0-generic\n##SABLE##\nx86_64\n##SABLE##\n'
              'uid=1000(auditor) gid=1000(auditor) groups=1000(auditor),27(sudo)\n')
    meta = parse_identity(output)
    assert meta['distro'] == 'ubuntu 22.04'
    assert meta['kernel'] == '5.15.0-generic'
    assert meta['user'] == 'auditor'
    assert meta['groups'] == ['auditor', 'sudo']
    assert meta['architecture'] == 'x86_64'


# --- EC-11 accounts and ssh -------------------------------------------------
def test_parse_accounts_includes_service_accounts_and_groups():
    accounts = parse_accounts(PASSWD, GROUP)
    by_name = {a['data']['name']: a['data'] for a in accounts}
    assert set(by_name) == {'root', 'www-data', 'auditor'}
    assert by_name['auditor']['groups'] == ['auditor', 'sudo']
    assert by_name['www-data']['shell'] == '/usr/sbin/nologin'


def test_parse_ssh_settings_marks_effective():
    ev = parse_ssh_settings('permitrootlogin no\npasswordauthentication yes\nport 22\n')
    by_name = {e['data']['name']: e['data'] for e in ev}
    assert by_name['PermitRootLogin']['value'] == 'no'
    assert by_name['PermitRootLogin']['effective'] is True
    assert 'PasswordAuthentication' in by_name
    assert 'Port' not in by_name  # not one of the five tracked settings


# --- EC-04 suid -------------------------------------------------------------
def test_parse_suid():
    out = '4755\troot\troot\t/usr/bin/find\n2755\troot\tshadow\t/usr/bin/wall\n'
    by_path = {e['data']['path']: e['data'] for e in parse_suid(out)}
    assert by_path['/usr/bin/find']['suid'] is True
    assert by_path['/usr/bin/find']['sgid'] is False
    assert by_path['/usr/bin/wall']['sgid'] is True
    assert by_path['/usr/bin/wall']['suid'] is False


# --- EC-05 permissions ------------------------------------------------------
def test_accessors_expands_other_read():
    accounts, members = _accounts()
    names = [a['data']['name'] for a in accounts]
    readable, writable = accessors('644', 'root', 'root', names, members)
    assert 'auditor' in readable  # world-readable
    assert writable == ['root']


def test_parse_permissions_shadow_readable_by_auditor():
    accounts, members = _accounts()
    ev = parse_permissions('644\troot\tshadow\t/etc/shadow\n', accounts, members)
    data = ev[0]['data']
    assert data['path'] == '/etc/shadow'
    assert 'auditor' in data['readable_by']


def test_parse_world_writable():
    accounts, members = _accounts()
    ev = parse_world_writable('666\troot\troot\t/tmp/x\n', accounts, members)
    assert 'auditor' in ev[0]['data']['writable_by']


# --- EC-09 capabilities -----------------------------------------------------
def test_parse_capabilities_both_formats():
    out = '/opt/python cap_setuid+ep\n/usr/bin/ping = cap_net_raw+ep\n'
    by_path = {e['data']['path']: e['data']['capabilities'] for e in parse_capabilities(out)}
    assert any('cap_setuid' in c for c in by_path['/opt/python'])
    assert any('cap_net_raw' in c for c in by_path['/usr/bin/ping'])


# --- EC-12 packages ---------------------------------------------------------
def test_parse_packages():
    out = 'bash\t5.1-6ubuntu1\tamd64\nlinux-image-5.15.0-generic\t5.15.0.1\tamd64\n'
    names = {e['data']['name']: e['data'] for e in parse_packages(out)}
    assert names['bash']['version'] == '5.1-6ubuntu1'
    assert 'linux-image-5.15.0-generic' in names


# --- EC-06 / EC-15 sudo -----------------------------------------------------
def test_parse_sudo_list():
    out = ('Matching Defaults entries for auditor:\n    env_reset\n\n'
           'User auditor may run the following commands on host:\n'
           '    (root) NOPASSWD: /usr/bin/find\n'
           '    (ALL : ALL) ALL\n')
    ev, password_required = parse_sudo_list(out, 0, 'auditor')
    assert password_required is False
    assert any(r['data']['nopasswd'] and r['data']['runas'] == 'root'
               and '/usr/bin/find' in r['data']['commands'] for r in ev)
    assert any(r['data']['runas'] == 'ALL' for r in ev)


def test_parse_sudo_list_password_required():
    ev, password_required = parse_sudo_list('sudo: a password is required\n', 1, 'auditor')
    assert password_required is True and ev == []


def test_parse_sudoers_skips_groups_and_comments():
    text = ('# header\nDefaults env_reset\n'
            'root ALL=(ALL:ALL) ALL\n'
            'dbadmin ALL=(root) NOPASSWD: /usr/bin/find\n'
            '%admin ALL=(ALL) ALL\n')
    users = {e['data']['user']: e['data'] for e in parse_sudoers(text)}
    assert 'root' in users and 'dbadmin' in users and 'admin' not in users
    assert users['dbadmin']['nopasswd'] is True
    assert '/usr/bin/find' in users['dbadmin']['commands']


# --- EC-07 scheduled --------------------------------------------------------
def test_parse_cron_and_assemble():
    cron_out = ('# /etc/crontab\n*/5 * * * * root /opt/backup.sh\n##SABLE##\n'
                '#file /etc/cron.d/clean\n0 2 * * * root /usr/local/bin/clean.sh\n##SABLE##\n'
                '* * * * * /home/auditor/job.sh\n##SABLE##\n')
    jobs = parse_cron(cron_out, 'auditor')
    by_path = {j['script_path']: j for j in jobs}
    assert by_path['/opt/backup.sh']['run_as'] == 'root'
    assert by_path['/home/auditor/job.sh']['run_as'] == 'auditor'

    accounts, members = _accounts()
    stat_rows = [('775', 'root', 'www-data', '/opt/backup.sh')]
    ev = assemble_scheduled(jobs, stat_rows, accounts, members)
    assert len(ev) == 1
    assert 'www-data' in ev[0]['data']['writable_by']
    assert ev[0]['data']['run_as'] == 'root'


# --- EC-08 services ---------------------------------------------------------
def test_parse_services():
    ss = ('tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
          'tcp   LISTEN 0 511 [::]:80 [::]:* users:(("apache2",pid=5,fd=4))\n')
    by_name = {e['data']['name']: e['data'] for e in parse_services(ss, '')}
    assert by_name['sshd']['listeners'][0]['port'] == 22
    assert by_name['apache2']['listeners'][0]['port'] == 80
    assert by_name['sshd']['running'] is True


# --- EC-10 credentials (redaction at source) --------------------------------
def test_scan_text_never_returns_secret_values():
    text = ('db_host = localhost\n'
            'db_password = "S3cr3t-LAB-ONLY"\n'
            'api_key: abcd1234efgh\n'
            '-----BEGIN RSA PRIVATE KEY-----\n'
            'url = mysql://user:p4ss@dbhost/app\n')
    matches = scan_text(text)
    flat = repr(matches)
    assert 'S3cr3t-LAB-ONLY' not in flat
    assert 'abcd1234efgh' not in flat
    assert 'p4ss' not in flat
    kinds = {kind for _line, kind in matches}
    assert {'password', 'token', 'private_key', 'connection_string'} <= kinds
    assert (2, 'password') in matches


def test_scan_text_ignores_placeholder():
    assert scan_text('password = changeme\n') == []
    assert scan_text('password = <your-password>\n') == []


def test_credential_evidence_shape():
    ev = credential_evidence('/var/www/config.php', [(4, 'password')], ['auditor', 'auditor'])
    assert len(ev) == 1
    data = ev[0]['data']
    assert data['path'] == '/var/www/config.php'
    assert data['line'] == 4
    assert data['pattern_type'] == 'password'
    assert data['readable_by'] == ['auditor']
    assert ev[0]['source_cmd'] == 'credential_scan'
