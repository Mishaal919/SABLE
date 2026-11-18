"""Filesystem runners for the gated apply/rollback boundary.

A runner exposes ``stat(path)`` and the two mutating operations ``chmod``/``chown``.
``LocalRunner`` uses subprocess with argument lists (never a shell) on the machine
SABLE runs on; tests use an in-memory fake. A remote runner over SSH would implement
the same three methods with a *write* allow-list, kept entirely separate from the
read-only collector.
"""
import subprocess

from sable.remediate.errors import RemediationError


class LocalRunner:
    """Runs chmod/chown/stat locally via argument lists (no shell)."""

    def stat(self, path):
        try:
            out = subprocess.run(['stat', '-c', '%a\t%U\t%G', path],
                                 capture_output=True, text=True, check=True, timeout=30).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise RemediationError(f'cannot stat {path}') from exc
        parts = out.split('\t')
        if len(parts) != 3:
            raise RemediationError(f'unexpected stat output for {path}')
        return parts[0], parts[1], parts[2]

    def chmod(self, mode, path):
        self._run(['chmod', mode, path])

    def chown(self, spec, path):
        self._run(['chown', spec, path])

    @staticmethod
    def _run(argv):
        try:
            subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RemediationError(f'command failed: {" ".join(argv)}') from exc
