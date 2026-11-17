"""Debian/Ubuntu package version comparison (dpkg --compare-versions logic).

Implements the algorithm from dpkg's lib/dpkg/version.c so the vulnerability
catalogue can compare distro package versions without an extra dependency.
"""
import re

_VALID = re.compile(r'^(?:(\d+):)?([0-9][A-Za-z0-9.+~:-]*?)(?:-([A-Za-z0-9.+~]+))?$')


def parse_version(text):
    """Split a version into (epoch, upstream, revision); raise ValueError if invalid."""
    if not isinstance(text, str):
        raise ValueError('Package version must be a string')
    text = text.strip()
    epoch = 0
    if ':' in text:
        head, text = text.split(':', 1)
        if not head.isdigit():
            raise ValueError('Invalid package version epoch')
        epoch = int(head)
    upstream, revision = (text.rsplit('-', 1) if '-' in text else (text, ''))
    if not upstream or not upstream[0].isdigit() or not _VALID.match(f'{epoch}:{text}'):
        raise ValueError('Invalid package version')
    return epoch, upstream, revision


def _order(char):
    if char == '':
        return 0
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    if char == '~':
        return -1
    return ord(char) + 256


def _compare_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i] if i < len(a) and not a[i].isdigit() else '')
            bc = _order(b[j] if j < len(b) and not b[j].isdigit() else '')
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        start_i, start_j = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        left, right = int(a[start_i:i] or 0), int(b[start_j:j] or 0)
        if left != right:
            return -1 if left < right else 1
    return 0


def compare_versions(left, right):
    """Return -1, 0 or 1 as left is lower than, equal to or higher than right."""
    a, b = parse_version(left), parse_version(right)
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    return _compare_part(a[1], b[1]) or _compare_part(a[2], b[2])
