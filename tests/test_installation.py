"""Check the installed entry point without pytest's project-path assistance."""
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig


def test_installed_report_command_outside_project(tmp_path):
    project = Path(__file__).resolve().parents[1]
    scripts = Path(sysconfig.get_path('scripts'))
    # pip installs a native sable.exe launcher on Windows and a Python script elsewhere.
    launcher = [str(scripts / 'sable.exe')] if os.name == 'nt' else [sys.executable, str(scripts / 'sable')]
    environment = os.environ.copy()
    environment.pop('PYTHONPATH', None)
    completed = subprocess.run(
        [*launcher, 'report',
         str(project / 'tests/fixtures/results/weak3.analysis.json')],
        cwd=tmp_path, env=environment, capture_output=True, text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert 'Top three fixes' in completed.stdout
    assert (tmp_path / 'output/report.html').is_file()
    result = json.loads((tmp_path / 'output/results.json').read_text(encoding='utf-8'))
    assert result['stage'] == 'complete'
