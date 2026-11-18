"""Shared parsing helpers for the evidence checks."""


def parse_stat_lines(text):
    """Parse tab-separated ``stat -c '%a\\t%U\\t%G\\t%n'`` output.

    Returns a list of ``(mode, owner, group, path)`` tuples, skipping blank or
    malformed lines. ``mode`` is kept as an octal string (e.g. ``"644"``/``"4755"``).
    """
    rows = []
    for line in text.splitlines():
        line = line.rstrip('\n')
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) != 4:
            continue
        mode, owner, group, path = (p.strip() for p in parts)
        if not mode or not path:
            continue
        rows.append((mode, owner, group, path))
    return rows


def group_members(accounts):
    """Map group name -> set of member account names, from parsed accounts.

    Accepts user_account *evidence* dicts (fields under ``data``) or plain account
    dicts (fields at the top level). ``groups`` lists every group the account belongs
    to, primary group included.
    """
    members = {}
    for account in accounts:
        data = account.get('data', account)
        name = data.get('name')
        if not name:
            continue
        for group in data.get('groups', ()):
            members.setdefault(group, set()).add(name)
    return members


def accessors(mode, owner, group, account_names, members):
    """Return ``(readable_by, writable_by)`` sorted user-name lists for a file.

    Expands owner/group/other permission bits into concrete account names using the
    collected accounts, so the analyzer (which matches an actor against these lists)
    sees names, not bits. root is always included; it can access everything.
    """
    try:
        bits = int(str(mode), 8)
    except ValueError:
        bits = 0
    readers, writers = {'root'}, {'root'}
    all_names = set(account_names) | {owner}
    group_names = set(members.get(group, set()))

    if bits & 0o400:
        readers.add(owner)
    if bits & 0o200:
        writers.add(owner)
    if bits & 0o040:
        readers |= group_names
    if bits & 0o020:
        writers |= group_names
    if bits & 0o004:
        readers |= all_names
    if bits & 0o002:
        writers |= all_names
    return sorted(readers), sorted(writers)


def normalise_mode(mode):
    """Clamp a stat mode string to the schema's 3-4 octal digits."""
    mode = str(mode).strip()
    if len(mode) > 4:
        mode = mode[-4:]
    return mode or '0'
