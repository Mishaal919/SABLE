"""SABLE command line: validate, analyze, scan, plan, report, remediate, rollback, compare.

Deterministic domain logic lives in the library modules; this file only parses
arguments, loads/writes files and maps failures to exit code 2. Heavy or optional
imports (collector, analyzer, reporter) are done lazily inside each handler.
"""
import argparse
import getpass
import json
import os
from pathlib import Path

import yaml

from sable.contracts.validation import ContractError, dumps, validate


def _load_config(path):
    if not path:
        path = Path('sable.yaml')
        if not path.is_file():
            return {}
    config = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ContractError('Configuration must be a mapping')
    return config


def _apply_overrides(config, path_cutoff):
    if path_cutoff is not None:
        config['path_cutoff'] = path_cutoff
    return config


def _secrets(names):
    secrets = []
    for name in names or []:
        if name not in os.environ:
            raise ContractError('A requested redaction environment variable is missing')
        secrets.append(os.environ[name])
    return secrets


def _report_complete(complete, output, secrets):
    """Redact, validate and write report.html/results.json/summary.txt; print summary."""
    from sable.redaction import redact
    from sable.report.html import write_report
    from sable.report.terminal import terminal_summary
    clean = redact(complete, secrets)
    validate(clean, 'results')
    write_report(clean, output)
    print(terminal_summary(clean), end='')


def _full_pipeline(snapshot, config, output, secrets):
    """snapshot -> analyze -> finalize -> VOI -> report (the scan/analyze core)."""
    from sable.graph.build import analyze
    from sable.fix.planner import finalize_results
    from sable.score.voi import compute_voi
    validate(snapshot, 'snapshot')
    analysis = analyze(snapshot, config)
    complete = finalize_results(analysis, config)
    complete['voi'] = compute_voi(complete, config)
    _report_complete(complete, output, secrets)
    return complete


def _handle_analyze(args):
    config = _apply_overrides(_load_config(args.config), args.path_cutoff)
    snapshot = json.loads(args.snapshot.read_text(encoding='utf-8'))
    _full_pipeline(snapshot, config, args.output, _secrets(args.redact_env))
    return 0


def _handle_scan(args):
    from sable.collect import collect_snapshot
    if '@' not in args.target:
        raise ContractError('scan target must be user@host')
    user, host = args.target.split('@', 1)
    config = _apply_overrides(_load_config(args.config), args.path_cutoff)
    ssh_config = config.get('ssh', {}) if isinstance(config.get('ssh'), dict) else {}
    password = None
    secrets = list(_secrets(args.redact_env))
    if args.password_env:
        if args.password_env not in os.environ:
            raise ContractError('The SSH password environment variable is not set')
        password = os.environ[args.password_env]
        secrets.append(password)
    elif not args.key:
        password = getpass.getpass('SSH password: ')
        if password:
            secrets.append(password)
    snapshot = collect_snapshot(
        host, user,
        port=args.port if args.port is not None else ssh_config.get('port', 22),
        key_path=str(args.key) if args.key else None,
        password=password,
        accept_new_host_key=args.accept_new_host_key if args.accept_new_host_key is not None else bool(ssh_config.get('accept_new_host_key')),
        timeout=ssh_config.get('command_timeout_seconds', 30),
        config={**config.get('scan', {}), 'elevated': args.elevated if args.elevated is not None else bool(config.get('scan', {}).get('elevated'))},
        audit_path=args.audit_log, assume_yes=args.yes, secrets=tuple(secrets),
    )
    _full_pipeline(snapshot, config, args.output, tuple(secrets))
    return 0


def _handle_remediate(args):
    from sable.remediate import apply_fixes, write_scripts, LocalRunner
    from sable.remediate.verification import preflight, verification_config, collect_after_apply, compare_after_apply
    from sable.redaction import redact
    if args.rescan and not args.apply:
        raise ContractError("--rescan requires --apply on the assessed Linux host")
    results = json.loads(args.file.read_text(encoding='utf-8'))
    validate(results, 'results')
    if results.get('stage') != 'complete':
        raise ContractError('remediate requires completed (stage=complete) results; run analyze or plan first')
    secrets = _secrets(args.redact_env)
    config = verification_config(results, _load_config(args.config))
    if args.rescan:
        preflight(results)
    written = write_scripts(results, args.output, secrets)
    for name, path in written.items():
        print(f'Wrote {path}')
    if args.apply:
        confirm = (lambda prompt: True) if args.yes else _prompt_yes
        state = apply_fixes(results, LocalRunner(), confirm=confirm, state_path=str(args.state))
        print(f'Applied {len(state["applied"])} fix(es); skipped {len(state["skipped"])}. State written to {args.state}')
        if args.rescan:
            output = args.output / 'rescan'
            output.mkdir(parents=True, exist_ok=True)
            snapshot = collect_after_apply(results, config, output / 'audit.log')
            (output / 'snapshot.json').write_text(dumps(redact(snapshot, secrets)), encoding='utf-8')
            after = _full_pipeline(snapshot, config, output, secrets)
            comparison = compare_after_apply(results, state, after, config)
            (output / 'comparison.json').write_text(dumps(redact(comparison, secrets)), encoding='utf-8')
            print(f'Rescan: predicted {comparison["predicted_residual_paths"]} paths; '
                  f'observed {comparison["actual_paths"]}; paths match: {comparison["paths_match"]}.')
    else:
        applyable = sum(1 for f in results.get('fixes', []) if f.get('execution') == 'script_and_apply')
        print(f'{applyable} applyable fix(es). Review the scripts, or re-run with --apply to change this host.')
    return 0


def _handle_rollback(args):
    from sable.remediate import rollback, LocalRunner
    restored = rollback(args.state, LocalRunner())
    print(f'Restored {len(restored)} path(s) from {args.state}')
    return 0


def _prompt_yes(prompt):
    try:
        return input(prompt).strip().lower() in ('y', 'yes')
    except EOFError:
        return False


def _handle_validate(args):
    data = json.loads(args.file.read_text(encoding='utf-8'))
    if args.snapshot and args.kind != 'results':
        raise ContractError('--snapshot is only valid for results')
    snapshot = json.loads(args.snapshot.read_text(encoding='utf-8')) if args.snapshot else None
    validate(data, args.kind, snapshot=snapshot)
    print(f'Valid {args.kind}: {args.file}')
    return 0


def _handle_compare(args):
    from sable.report.compare import compare_scans
    from sable.redaction import redact
    before, after = (json.loads(p.read_text(encoding='utf-8')) for p in (args.before, args.after))
    validate(before, 'results')
    validate(after, 'results')
    print(dumps(redact(compare_scans(before, after))), end='')
    return 0


def _handle_plan_or_report(args):
    from sable.fix.planner import finalize_results
    from sable.redaction import redact
    data = json.loads(args.file.read_text(encoding='utf-8'))
    config = _apply_overrides(_load_config(args.config), args.path_cutoff)
    validate(data, 'results')
    result = finalize_results(data, config) if (args.command == 'plan' or data['stage'] == 'analysis' or config) else data
    if args.command == 'plan':
        clean = redact(result, _secrets(args.redact_env))
        validate(clean, 'results')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(dumps(clean), encoding='utf-8')
        from sable.report.terminal import terminal_summary
        print(terminal_summary(clean), end='')
    else:
        _report_complete(result, args.output, _secrets(args.redact_env))
    return 0


def _build_parser():
    parser = argparse.ArgumentParser(description='SABLE: read-only Linux security assessment')
    sub = parser.add_subparsers(dest='command', required=True)

    validate_cmd = sub.add_parser('validate', help='Validate a snapshot or results file')
    validate_cmd.add_argument('kind', choices=['snapshot', 'results'])
    validate_cmd.add_argument('file', type=Path)
    validate_cmd.add_argument('--snapshot', type=Path)

    analyze_cmd = sub.add_parser('analyze', help='Analyse a snapshot and write a full report (no SSH)')
    analyze_cmd.add_argument('snapshot', type=Path, help='Validated snapshot JSON')
    analyze_cmd.add_argument('--config', type=Path)
    analyze_cmd.add_argument('--path-cutoff', type=int)
    analyze_cmd.add_argument('--output', type=Path, default=Path('output'))
    analyze_cmd.add_argument('--redact-env', action='append', default=[], metavar='NAME')

    scan_cmd = sub.add_parser('scan', help='Collect over SSH, analyse and write a full report')
    scan_cmd.add_argument('target', help='user@host')
    scan_cmd.add_argument('--port', type=int)
    scan_cmd.add_argument('--key', type=Path, help='SSH private key file')
    scan_cmd.add_argument('--password-env', metavar='NAME', help='env var holding the SSH password')
    scan_cmd.add_argument('--accept-new-host-key', action=argparse.BooleanOptionalAction, default=None)
    scan_cmd.add_argument('--elevated', action=argparse.BooleanOptionalAction, default=None)
    scan_cmd.add_argument('--yes', action='store_true', help='skip the authorisation prompt (CI)')
    scan_cmd.add_argument('--config', type=Path)
    scan_cmd.add_argument('--path-cutoff', type=int)
    scan_cmd.add_argument('--output', type=Path, default=Path('output'))
    scan_cmd.add_argument('--audit-log', default='audit.log')
    scan_cmd.add_argument('--redact-env', action='append', default=[], metavar='NAME')

    for name, help_text in [('plan', 'Plan fixes for a supplied analysis graph'),
                            ('report', 'Plan if needed and write HTML, JSON and terminal summary')]:
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument('file', type=Path, help='Validated analysis or completed results JSON')
        cmd.add_argument('--config', type=Path, help='Scoring/planner YAML settings')
        cmd.add_argument('--path-cutoff', type=int, help='Override config path cutoff')
        cmd.add_argument('--output', type=Path, default=Path('output/results.json' if name == 'plan' else 'output'))
        cmd.add_argument('--redact-env', action='append', default=[], metavar='NAME',
                         help='Environment variable containing a secret to redact (repeatable)')

    remediate_cmd = sub.add_parser('remediate', help='Generate fix/rollback scripts; optionally apply chmod/chown fixes')
    remediate_cmd.add_argument('file', type=Path, help='Completed results JSON')
    remediate_cmd.add_argument('--output', type=Path, default=Path('output'))
    remediate_cmd.add_argument('--apply', action='store_true', help='apply chmod/chown fixes on this host (gated)')
    remediate_cmd.add_argument('--rescan', action='store_true', help='rescan this Linux host as the original scan account after applying')
    remediate_cmd.add_argument('--config', type=Path)
    remediate_cmd.add_argument('--redact-env', action='append', default=[], metavar='NAME')
    remediate_cmd.add_argument('--state', type=Path, default=Path('state.json'))
    remediate_cmd.add_argument('--yes', action='store_true', help='apply without per-change confirmation')

    rollback_cmd = sub.add_parser('rollback', help='Restore files recorded in a remediation state.json')
    rollback_cmd.add_argument('state', type=Path)

    compare_cmd = sub.add_parser('compare', help='Compare two scans by path structure')
    compare_cmd.add_argument('before', type=Path)
    compare_cmd.add_argument('after', type=Path)
    return parser


_HANDLERS = {
    'validate': _handle_validate,
    'analyze': _handle_analyze,
    'scan': _handle_scan,
    'plan': _handle_plan_or_report,
    'report': _handle_plan_or_report,
    'remediate': _handle_remediate,
    'rollback': _handle_rollback,
    'compare': _handle_compare,
}


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return _HANDLERS[args.command](args)
    except (OSError, UnicodeError, json.JSONDecodeError):
        parser.exit(2, 'Cannot read or write a valid input/output file.\n')
    except ContractError as error:
        parser.exit(2, f'{error}\n')
    except yaml.YAMLError:
        parser.exit(2, 'Invalid YAML configuration.\n')
    except (ValueError, TypeError, KeyError):
        parser.exit(2, 'Invalid planning data or configuration.\n')
    except _collector_errors():
        parser.exit(2, 'Collection or remediation failed.\n')


def _collector_errors():
    """Lazily resolve collector/remediation error classes for a clean exit code 2."""
    try:
        from sable.collect.errors import CollectorError
    except Exception:
        CollectorError = ()
    try:
        from sable.remediate.errors import RemediationError
    except Exception:
        RemediationError = ()
    classes = tuple(c for c in (CollectorError, RemediationError) if isinstance(c, type))
    return classes or (Exception,)


if __name__ == '__main__':
    raise SystemExit(main())
