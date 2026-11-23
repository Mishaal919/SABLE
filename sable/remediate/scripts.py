"""Generate reviewed chmod/chown operations and a protected, reusable rollback log."""
import shlex
from sable.redaction import redact
from sable.remediate.operations import is_applyable, parse_operations

STATE_DEFAULT = 'sable-remediation-state.tsv'


def _comment(text):
    # Every line is a comment, including untrusted descriptions/manual commands.
    return ['# ' + line for line in str(text).splitlines()]


def _fix_script(fixes):
    lines = ['#!/usr/bin/env bash', 'set -euo pipefail', 'umask 077',
             '# Apply on the assessed Linux host only. Review before running.',
             f'STATE="${{SABLE_STATE:-{STATE_DEFAULT}}}"',
             '# Never overwrite an earlier recovery log, including a symlink.',
             '(set -o noclobber; : > "$STATE") || { echo "State already exists; choose a new SABLE_STATE." >&2; exit 2; }',
             'record() {',
             '  [[ ! -L "$1" && ( -f "$1" || -d "$1" ) ]] || { echo "Unsupported file type" >&2; exit 2; }',
             '  stat --printf="%n\\t%a\\t%u\\t%g\\n" -- "$1" >> "$STATE"',
             '}']
    selected, paths, manual = [], set(), []
    for fix in fixes:
        if is_applyable(fix):
            operations = parse_operations(fix['command'])
            selected.append((fix, operations))
            paths.update(op.path for op in operations)
        else:
            manual.extend(_comment(f"{fix['id']} ({fix['type']}, recommend-only): {fix['description']}"))
            manual.extend(_comment(fix['command']))
    # Record each original once, before any mutation (fixes may share paths).
    for path in sorted(paths):
        lines.append(f'record {shlex.quote(path)}')
    for fix, operations in selected:
        lines.extend(_comment(f"{fix['id']} ({fix['type']}): {fix['description']}"))
        for op in operations:
            lines.append(shlex.join([op.verb, op.argument, op.path]))
    if manual:
        lines.append('# Manual recommendations (NOT applied by this script):')
        lines.extend(manual)
    return '\n'.join(lines) + '\n', len(selected)


def _rollback_script():
    return '\n'.join([
        '#!/usr/bin/env bash', 'set -euo pipefail',
        f'STATE="${{SABLE_STATE:-{STATE_DEFAULT}}}"',
        '[[ -f "$STATE" && ! -L "$STATE" ]] || { echo "Missing regular state file" >&2; exit 2; }',
        '# Validate every record before changing anything.',
        "while IFS=$'\\t' read -r path mode owner group extra; do",
        '  [[ "$path" == /* && "$path" != / && "$path" != */../* && "$path" != */.. && -z "$extra" ]] || exit 2',
        '  [[ "$mode" =~ ^[0-7]{1,4}$ && "$owner" =~ ^[0-9]+$ && "$group" =~ ^[0-9]+$ ]] || exit 2',
        '  [[ ! -L "$path" && ( -f "$path" || -d "$path" ) ]] || exit 2',
        'done < "$STATE"',
        "while IFS=$'\\t' read -r path mode owner group; do",
        '  chown "$owner:$group" "$path"',
        '  chmod "$mode" "$path"',
        'done < "$STATE"', ''])


def generate_scripts(results, secrets=()):
    fixes = redact(results.get('fixes', []), secrets)
    fix_text, applied = _fix_script(fixes)
    return {'fix.sh': fix_text, 'rollback.sh': _rollback_script(), 'applied': applied}


def write_scripts(results, output_dir, secrets=()):
    from pathlib import Path
    scripts = generate_scripts(results, secrets)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    written = {}
    for name in ('fix.sh', 'rollback.sh'):
        path = output / name
        path.write_text(scripts[name], encoding='utf-8', newline='\n')
        path.chmod(0o700)
        written[name] = path
    return written
