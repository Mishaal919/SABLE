"""RM-02 / RM-05: optional gated apply mode and rescan comparison.

Only chmod/chown fixes are applied. The original owner/mode of every touched path is
recorded to state.json *before* any change, each change is confirmed, and sudo/service
fixes are refused (RM-04). RM-05 compares an actual rescan against the predicted
residual. Nothing here runs a command string from the results file; it executes
parsed, validated operations via a runner.
"""

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


def apply_fixes(results, runner, confirm=lambda prompt: False, state_path=None):
    """Persist recovery data before each confirmed change; preserve partial failures."""
    from sable.remediate.state import save_state
    fixes = results.get('fixes', [])
    parsed = {}
    if len({f['id'] for f in fixes}) != len(fixes):
        raise UnsafeFix('Duplicate fix IDs')
    for fix in fixes:
        if fix.get('execution') == 'script_and_apply' and not is_applyable(fix):
            raise UnsafeFix('Only chmod/chown fixes may be applied')
        if is_applyable(fix):
            parsed[fix['id']] = parse_operations(fix['command'])
    # Confirm before statting, so declined fixes are never included in rollback.
    accepted, skipped = [], []
    for fix in fixes:
        if fix['id'] in parsed and confirm(f'Apply locally {fix["id"]} ({fix["type"]}): {fix["description"]}? [y/N] '):
            accepted.append(fix)
        else:
            skipped.append(fix['id'])
    state = {'originals': record_original_state(accepted, runner), 'applied': [],
             'skipped': skipped, 'started': [], 'status': 'prepared'}
    save_state(state_path, state, create=True)
    try:
        for fix in accepted:
            state['started'].append(fix['id'])
            state['status'] = 'applying'
            save_state(state_path, state)
            for operation in parsed[fix['id']]:
                getattr(runner, operation.verb)(operation.argument, operation.path)
            state['applied'].append(fix['id'])
            save_state(state_path, state)
    except Exception:
        state['status'] = 'failed'
        save_state(state_path, state)
        raise
    state['status'] = 'complete'
    save_state(state_path, state)
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
