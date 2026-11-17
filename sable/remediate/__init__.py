"""SABLE remediation (Thomas): a separate, explicitly gated boundary from collection.

- RM-01/RM-04: :func:`generate_scripts` / :func:`write_scripts` - fix.sh + rollback.sh,
  chmod/chown only; sudo/service/capability/manual are commented recommendations.
- RM-02/RM-05: :func:`apply_fixes` (gated, records state.json first) and
  :func:`residual_matches` (rescan vs predicted residual).
- RM-03: :func:`rollback` / :func:`rollback_from_state`.

Fixes are applied as parsed, validated chmod/chown operations, never by executing a
command string from a results file.
"""
from sable.remediate.apply import apply_fixes, record_original_state, residual_matches
from sable.remediate.errors import RemediationError, UnsafeFix
from sable.remediate.operations import Operation, is_applyable, parse_operations, paths_of
from sable.remediate.rollback import rollback, rollback_from_state
from sable.remediate.runner import LocalRunner
from sable.remediate.scripts import generate_scripts, write_scripts

__all__ = [
    'generate_scripts', 'write_scripts',
    'apply_fixes', 'record_original_state', 'residual_matches',
    'rollback', 'rollback_from_state', 'LocalRunner',
    'parse_operations', 'is_applyable', 'paths_of', 'Operation',
    'RemediationError', 'UnsafeFix',
]
