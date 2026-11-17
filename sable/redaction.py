"""Shared output redaction. Collection must still avoid retaining secrets at source."""
import re
import unicodedata

_MARKER = '[REDACTED]'
_PRIVATE = re.compile(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', re.S)
_ASSIGNMENT = re.compile(r'''(?i)(\b(?:password|passwd|pwd|token|api[_-]?key|secret)\b\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)''')
_BEARER = re.compile(r'(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+')
_URI = re.compile(r'(://[^\s/:@]+:)[^\s/@]+(@)')


def redact(value, secrets=()):
    """Return a copy with known literal secrets and common secret patterns removed.

    Pass session passwords/tokens via secrets. Pattern matching cannot identify
    arbitrary unlabelled secrets. Call before HTML escaping or JSON serialisation.
    """
    secrets = tuple(sorted({s for s in secrets if isinstance(s, str) and s}, key=len, reverse=True))
    if isinstance(value, str):
        value = _PRIVATE.sub(_MARKER, value)
        for secret in secrets:
            value = value.replace(secret, _MARKER)
        value = _ASSIGNMENT.sub(lambda m: m[1] + _MARKER, value)
        value = _BEARER.sub(lambda m: m[1] + _MARKER, value)
        value = _URI.sub(lambda m: m[1] + _MARKER + m[2], value)
        return ''.join(c for c in value if c in '\n\t' or not unicodedata.category(c).startswith('C'))
    if isinstance(value, dict):
        return {redact(k, secrets): redact(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    return value
