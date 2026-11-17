"""EC-10 / CL-05: credential scan with redaction *at the source*.

:func:`scan_text` returns only the line number and the kind of secret it saw. The
matched value is never returned, logged or stored — the file text stays in memory
for the duration of the scan and is then discarded by the caller. This is the first
line of defence; the shared redactor is applied again before any write.
"""
import re

# Checked most-specific first; the first matching kind wins for a line.
_PATTERNS = [
    ('private_key', re.compile(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----')),
    ('connection_string', re.compile(r'[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:[^\s/@]+@')),
    # No leading word boundary: config keys are often prefixed (db_password, api_key),
    # and '_' is a word char so '\b' would miss them. A trailing boundary + the
    # assignment operator keep false positives low.
    ('token', re.compile(r'(?i)(?:api[_-]?key|access[_-]?key|client[_-]?secret|secret|token)\b\s*[:=]\s*[^\s,;]')),
    ('password', re.compile(r'(?i)(?:password|passwd|pwd)\b\s*[:=]\s*[^\s,;]')),
]

# A placeholder value is not a real secret; ignore obvious examples.
_PLACEHOLDER = re.compile(r'(?i)(changeme|example|your[_-]?password|<[^>]+>|\$\{[^}]+\}|xxxx+)')


def scan_text(text):
    """Return a sorted list of ``(line_number, pattern_type)`` for secrets found.

    Never returns the secret value. Line numbers are 1-based.
    """
    found = []
    for index, line in enumerate(text.splitlines(), start=1):
        for pattern_type, pattern in _PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            # Skip lines that only contain a placeholder after the assignment.
            tail = line[match.start():]
            if pattern_type in ('password', 'token') and _PLACEHOLDER.search(tail):
                break
            found.append((index, pattern_type))
            break
    return sorted(set(found))


def credential_evidence(path, matches, readable_by):
    """Build credential_location evidence from :func:`scan_text` matches.

    One evidence item per ``(line, pattern_type)``; carries path, line and pattern
    type only, plus who can read the file. No secret value is present.
    """
    evidence = []
    for line, pattern_type in matches:
        evidence.append({
            'type': 'credential_location',
            'data': {
                'path': path,
                'line': line,
                'pattern_type': pattern_type,
                'readable_by': sorted(set(readable_by)) or ['root'],
            },
            'source_cmd': 'credential_scan',
            'strength': 'observed',
        })
    return evidence
