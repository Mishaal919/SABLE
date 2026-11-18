"""EC-11: user accounts and SSH daemon settings."""

# Every /etc/passwd account is emitted, service accounts (www-data) included: the
# analyzer decides which are interactive (uid >= 1000, login shell), while group
# membership expansion for writable_by/readable_by needs the service accounts too.

_SSH_KEYS = {
    'permitrootlogin': 'PermitRootLogin',
    'passwordauthentication': 'PasswordAuthentication',
    'pubkeyauthentication': 'PubkeyAuthentication',
    'permitemptypasswords': 'PermitEmptyPasswords',
    'protocol': 'Protocol',
}


def _parse_group_file(text):
    """Return group-name -> list of explicit members from ``getent group``."""
    members = {}
    gid_to_name = {}
    for line in text.splitlines():
        parts = line.split(':')
        if len(parts) < 4:
            continue
        name, _pw, gid, member_csv = parts[0], parts[1], parts[2], parts[3]
        gid_to_name[gid] = name
        members[name] = [m for m in member_csv.split(',') if m]
    return members, gid_to_name


def parse_accounts(passwd_text, group_text=''):
    """Parse ``getent passwd`` (+ ``getent group``) into user_account evidence.

    Only login-capable accounts are emitted. Each account's ``groups`` list contains
    its primary group plus every supplementary group, so downstream permission
    expansion can resolve group membership to names.
    """
    group_members, gid_to_name = _parse_group_file(group_text)
    evidence = []
    for line in passwd_text.splitlines():
        parts = line.split(':')
        if len(parts) < 7:
            continue
        name, _pw, uid, gid, _gecos, home, shell = parts[:7]
        if not name or not uid.isdigit() or not gid.isdigit():
            continue
        groups = []
        primary = gid_to_name.get(gid)
        if primary:
            groups.append(primary)
        for gname, gmembers in group_members.items():
            if name in gmembers and gname not in groups:
                groups.append(gname)
        evidence.append({
            'type': 'user_account',
            'data': {
                'name': name,
                'uid': int(uid),
                'gid': int(gid),
                'groups': sorted(dict.fromkeys(groups)) or [name],
                'home': home or '/',
                'shell': shell or '/bin/sh',
            },
            'source_cmd': 'user_accounts',
            'strength': 'observed',
        })
    return evidence


def parse_ssh_settings(effective_text, config_text=''):
    """Parse ``sshd -T`` (preferred) or ``sshd_config`` into ssh_setting evidence."""
    effective = bool(effective_text.strip())
    text = effective_text if effective else config_text
    seen = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, _, value = line.partition(' ')
        canonical = _SSH_KEYS.get(key.strip().lower())
        if canonical and canonical not in seen and value.strip():
            seen[canonical] = value.strip().split()[0]
    return [
        {
            'type': 'ssh_setting',
            'data': {'name': name, 'value': value, 'effective': effective},
            'source_cmd': 'ssh_settings',
            'strength': 'observed',
        }
        for name, value in seen.items()
    ]
