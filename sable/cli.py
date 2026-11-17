"""Offline contract validation, fix planning and report commands."""
import argparse
import json
import os
from pathlib import Path
import yaml
from sable.contracts.validation import ContractError, dumps, validate


def main(argv=None):
    parser = argparse.ArgumentParser(description='SABLE offline planning and reporting')
    sub = parser.add_subparsers(dest='command', required=True)
    command = sub.add_parser('validate', help='Validate a snapshot or results file')
    command.add_argument('kind', choices=['snapshot', 'results'])
    command.add_argument('file', type=Path)
    command.add_argument('--snapshot', type=Path)
    for name, help_text in [('plan', 'Plan fixes for a supplied analysis graph'), ('report', 'Plan if needed and write HTML, JSON and terminal summary')]:
        command = sub.add_parser(name, help=help_text)
        command.add_argument('file', type=Path, help='Validated analysis or completed results JSON')
        command.add_argument('--config', type=Path, help='Scoring/planner YAML settings')
        command.add_argument('--path-cutoff', type=int, help='Override config path cutoff')
        command.add_argument('--output', type=Path, default=Path('output/results.json' if name == 'plan' else 'output'))
        command.add_argument('--redact-env', action='append', default=[], metavar='NAME', help='Environment variable containing a secret to redact (repeatable)')
    command = sub.add_parser('compare', help='Compare two scans by path structure')
    command.add_argument('before', type=Path)
    command.add_argument('after', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'compare':
            from sable.report.compare import compare_scans
            from sable.redaction import redact
            before, after = (json.loads(p.read_text(encoding='utf-8')) for p in (args.before, args.after))
            validate(before, 'results'); validate(after, 'results')
            print(dumps(redact(compare_scans(before, after))), end='')
            return 0
        data = json.loads(args.file.read_text(encoding='utf-8'))
        if args.command == 'validate':
            if args.snapshot and args.kind != 'results':
                raise ContractError('--snapshot is only valid for results')
            snapshot = json.loads(args.snapshot.read_text(encoding='utf-8')) if args.snapshot else None
            validate(data, args.kind, snapshot=snapshot)
            print(f'Valid {args.kind}: {args.file}')
            return 0
        from sable.fix.planner import finalize_results
        from sable.redaction import redact
        from sable.report.html import write_report
        from sable.report.terminal import terminal_summary
        config = {}
        if args.config:
            config = yaml.safe_load(args.config.read_text(encoding='utf-8'))
            if not isinstance(config, dict):
                raise ContractError('Planner config must be a mapping')
        if args.path_cutoff is not None:
            config['path_cutoff'] = args.path_cutoff
        secrets = []
        for name in args.redact_env:
            if name not in os.environ:
                raise ContractError('A requested redaction environment variable is missing')
            secrets.append(os.environ[name])
        validate(data, 'results')
        result = finalize_results(data, config) if args.command == 'plan' or data['stage'] == 'analysis' or config else data
        clean = redact(result, secrets)
        validate(clean, 'results')
        if args.command == 'plan':
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(dumps(clean), encoding='utf-8')
        else:
            write_report(clean, args.output)
        print(terminal_summary(clean), end='')
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError):
        parser.exit(2, 'Cannot read or write a valid input/output file.\n')
    except ContractError as error:
        parser.exit(2, f'{error}\n')
    except yaml.YAMLError:
        parser.exit(2, 'Invalid YAML configuration.\n')
    except (ValueError, TypeError, KeyError):
        parser.exit(2, 'Invalid planning data or configuration.\n')


if __name__ == '__main__':
    raise SystemExit(main())
