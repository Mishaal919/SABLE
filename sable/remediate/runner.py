"""Local chmod/chown runner. Remote writes never use the collector's SSH channel."""
import os
import stat
import subprocess
from sable.remediate.errors import RemediationError
from sable.remediate.operations import validate_operation


class LocalRunner:
    def stat(self, path):
        try:
            info = os.lstat(path)
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise RemediationError('Only regular files and directories can be remediated')
            return format(stat.S_IMODE(info.st_mode), '03o'), str(info.st_uid), str(info.st_gid)
        except OSError as exc:
            raise RemediationError('Cannot read target file metadata') from exc

    def chmod(self, mode, path):
        validate_operation('chmod', mode, path)
        self.stat(path)
        self._run(['chmod', mode, path])

    def chown(self, spec, path):
        validate_operation('chown', spec, path)
        self.stat(path)
        self._run(['chown', spec, path])

    @staticmethod
    def _run(argv):
        try:
            subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RemediationError('Filesystem operation failed; recovery state has been retained') from exc
