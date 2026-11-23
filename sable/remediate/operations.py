"""Parse display commands into validated operations; never execute source strings."""
import posixpath
import re
import shlex

from sable.remediate.errors import UnsafeFix

_MODE = re.compile(r'[0-7]{3,4}')
_OWNER = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?')
# A deliberately small filename grammar shared by scripts, apply and rollback.
_PATH = re.compile(r'/[A-Za-z0-9_./ @%+=,:~-]+')


class Operation:
    __slots__ = ('verb', 'argument', 'path')

    def __init__(self, verb, argument, path):
        self.verb, self.argument, self.path = verb, argument, path

    def __eq__(self, other):
        return isinstance(other, Operation) and (self.verb, self.argument, self.path) == (other.verb, other.argument, other.path)

    def __repr__(self):
        return f'Operation({self.verb!r}, {self.argument!r}, {self.path!r})'


def validate_operation(verb, argument, path):
    if verb not in ('chmod', 'chown'):
        raise UnsafeFix('Only chmod/chown operations are supported')
    pattern = _MODE if verb == 'chmod' else _OWNER
    if not isinstance(argument, str) or not pattern.fullmatch(argument):
        raise UnsafeFix('Invalid operation argument')
    if (not isinstance(path, str) or not _PATH.fullmatch(path)
            or posixpath.normpath(path) != path or path == '/' or path.startswith('//')):
        raise UnsafeFix('Invalid, non-canonical or unsafe path')
    return Operation(verb, argument, path)


def parse_operations(command):
    if not isinstance(command, str) or any(c in command for c in '\n\r\0'):
        raise UnsafeFix('Commands must be single-line strings')
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars='&|;')
        lexer.whitespace_split = True
        lexer.commenters = ''
        tokens = list(lexer)
    except ValueError as exc:
        raise UnsafeFix('Malformed command quoting') from exc
    segments, current = [], []
    for token in tokens:
        if token == '&&':
            if not current:
                raise UnsafeFix('Empty operation in command')
            segments.append(current)
            current = []
        else:
            current.append(token)
    if not current:
        raise UnsafeFix('Empty operation in command')
    segments.append(current)
    operations = []
    for segment in segments:
        if len(segment) != 3:
            raise UnsafeFix('Expected chmod/chown, argument and absolute path')
        operations.append(validate_operation(*segment))
    return operations


def is_applyable(fix):
    return fix.get('execution') == 'script_and_apply' and fix.get('type') in ('chmod', 'chown')


def paths_of(fix):
    return sorted({op.path for op in parse_operations(fix['command'])})
