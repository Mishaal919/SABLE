"""CL-01: analyze, scan, remediate and rollback CLI subcommands."""
import json
import pathlib

import pytest

import sable.collect
from sable.cli import main

ROOT = pathlib.Path(__file__).resolve().parents[1]
SNAP = ROOT / 'tests' / 'fixtures' / 'snapshots'
RESULTS = ROOT / 'tests' / 'fixtures' / 'results'
TARGETS = ROOT / 'targets'


def test_analyze_writes_full_report(tmp_path):
    out = tmp_path / 'report'
    assert main(['analyze', str(SNAP / 'weak3.json'), '--output', str(out)]) == 0
    assert (out / 'report.html').is_file()
    result = json.loads((out / 'results.json').read_text(encoding='utf-8'))
    assert result['stage'] == 'complete'
    # weak3 has two High paths; the report is the full pipeline output.
    assert any(p['band'] == 'High' for p in result['paths'])


def test_analyze_populates_voi_for_weak1(tmp_path):
    out = tmp_path / 'report'
    assert main(['analyze', str(SNAP / 'weak1.json'), '--output', str(out)]) == 0
    result = json.loads((out / 'results.json').read_text(encoding='utf-8'))
    # weak1's synthetic fixture has no unknowns, so VOI is empty but present and valid.
    assert isinstance(result['voi'], list)


def test_scan_runs_pipeline_with_collected_snapshot(tmp_path, monkeypatch):
    snapshot = json.loads((TARGETS / 'weak1' / 'snapshot.json').read_text(encoding='utf-8'))

    def fake_collect(host, user, **kwargs):
        assert user == 'auditor' and host == 'host.example'
        assert kwargs['assume_yes'] is True
        return snapshot

    monkeypatch.setattr(sable.collect, 'collect_snapshot', fake_collect)
    monkeypatch.setenv('SABLE_TEST_PW', 'pw')
    out = tmp_path / 'report'
    code = main(['scan', 'auditor@host.example', '--password-env', 'SABLE_TEST_PW',
                 '--yes', '--output', str(out)])
    assert code == 0
    result = json.loads((out / 'results.json').read_text(encoding='utf-8'))
    assert result['stage'] == 'complete'
    assert any(p['goal'] == 'root' for p in result['paths'])


def test_remediate_writes_scripts(tmp_path):
    out = tmp_path / 'fixes'
    assert main(['remediate', str(RESULTS / 'weak3.json'), '--output', str(out)]) == 0
    assert (out / 'fix.sh').is_file() and (out / 'rollback.sh').is_file()
    fix_sh = (out / 'fix.sh').read_text(encoding='utf-8')
    assert 'chmod 640 /etc/shadow' in fix_sh


def _exit_code(argv):
    with pytest.raises(SystemExit) as info:
        main(argv)
    return info.value.code


def test_remediate_requires_complete_results(tmp_path):
    # An analysis-stage file is not remediable; exit code 2.
    assert _exit_code(['remediate', str(RESULTS / 'weak3.analysis.json'), '--output', str(tmp_path)]) == 2


def test_rollback_missing_state_is_clean_error(tmp_path):
    assert _exit_code(['rollback', str(tmp_path / 'nope.json')]) == 2


def test_scan_bad_target_is_clean_error():
    assert _exit_code(['scan', 'not-a-target', '--yes']) == 2
