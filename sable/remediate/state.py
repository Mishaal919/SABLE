"""Durable per-run recovery records; never overwrite an earlier run on creation."""
import json
import os
import tempfile
from pathlib import Path
from sable.remediate.errors import RemediationError


def save_state(path, state, *, create=False):
    if path is None:
        return
    path = Path(path)
    data = json.dumps(state, indent=2, sort_keys=True, allow_nan=False) + '\n'
    if create:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise RemediationError('State file already exists; choose a new --state path') from exc
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        return
    fd, temporary = tempfile.mkstemp(prefix='.sable-state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
