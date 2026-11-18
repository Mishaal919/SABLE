"""Typed remediation errors.

Remediation is a separate, explicitly gated boundary from collection. It never runs
arbitrary command strings from a results file; it parses the intended chmod/chown
operation and runs it with safe arguments.
"""


class RemediationError(Exception):
    """Base class for remediation failures."""


class UnsafeFix(RemediationError):
    """A fix cannot be applied safely (not a chmod/chown, or malformed arguments)."""
