"""RM-03: restore every path recorded in a state.json to its original owner/mode."""
import json
from pathlib import Path

from sable.remediate.errors import RemediationError


def rollback_from_state(state, runner):
    """Restore owner then mode for every recorded original. Returns restored paths."""
    originals = state.get('originals')
    if not isinstance(originals, list):
        raise RemediationError('state file has no "originals" list')
    restored = []
    for original in originals:
        try:
            path, mode = original['path'], original['mode']
            spec = f'{original["owner"]}:{original["group"]}'
        except (KeyError, TypeError) as exc:
            raise RemediationError('malformed original-state record') from exc
        runner.chown(spec, path)
        runner.chmod(mode, path)
        restored.append(path)
    return restored


def rollback(state_path, runner):
    """Load a state.json written by apply_fixes and restore every recorded path."""
    try:
        state = json.loads(Path(state_path).read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RemediationError(f'cannot read state file {state_path}') from exc
    return rollback_from_state(state, runner)
