"""RM-02 / RM-05: optional gated apply mode and rescan comparison.

Only chmod/chown fixes are applied. The original owner/mode of every touched path is
recorded to state.json *before* any change, each change is confirmed, and sudo/service
fixes are refused (RM-04). RM-05 compares an actual rescan against the predicted
residual. Nothing here runs a command string from the results file; it executes
parsed, validated operations via a runner.
"""
import json
from pathlib import Path

from sable.remediate.errors import UnsafeFix
from sable.remediate.operations import is_applyable, parse_operations, paths_of


def record_original_state(fixes, runner):
    """Stat every path the applyable fixes touch; return a list of original records."""
    originals = []
    seen = set()
    for fix in fixes:
        if not is_applyable(fix):
            continue
        for path in paths_of(fix):
            if path in seen:
                continue
            seen.add(path)
            mode, owner, group = runner.stat(path)
            originals.append({'path': path, 'mode': mode, 'owner': owner, 'group': group, 'fix_id': fix['id']})
    return originals


def apply_fixes(results, runner, confirm=lambda prompt: True, state_path=None):
    """Apply the selected chmod/chown fixes, gated by ``confirm``.

    Writes the original state to ``state_path`` (JSON) before applying anything so a
    rollback is always possible. Returns the state dict with ``originals``, ``applied``
    and ``skipped``. Raises UnsafeFix if a non-chmod/chown fix is explicitly applyable.
    """
    fixes = results.get('fixes', [])
    for fix in fixes:
        if fix.get('type') in ('sudo', 'service') and fix.get('execution') == 'script_and_apply':
            raise UnsafeFix(f'{fix["type"]} fixes are never applied automatically (RM-04)')

    applyable = [fix for fix in fixes if is_applyable(fix)]
    originals = record_original_state(applyable, runner)
    state = {'originals': originals, 'applied': [], 'skipped': [f['id'] for f in fixes if not is_applyable(f)]}
    if state_path:
        Path(state_path).write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')

    for fix in applyable:
        if not confirm(f'Apply {fix["id"]} ({fix["type"]}): {fix["description"]}? [y/N] '):
            state['skipped'].append(fix['id'])
            continue
        for operation in parse_operations(fix['command']):
            getattr(runner, operation.verb)(operation.argument, operation.path)
        state['applied'].append(fix['id'])

    if state_path:
        Path(state_path).write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return state


def residual_matches(results, rescan_results):
    """RM-05: compare the predicted residual path count with an actual rescan.

    ``results`` is the completed results used for remediation; ``rescan_results`` is a
    fresh analysis/complete result after applying fixes. Returns a dict with the
    predicted and actual path counts and whether they match.
    """
    residual = results.get('residual') or {}
    predicted = len(residual.get('paths', []))
    actual = len(rescan_results.get('paths', []))
    return {'predicted_residual_paths': predicted, 'actual_paths': actual, 'match': predicted == actual}
