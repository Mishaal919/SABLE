"""Parse a fix's display command into safe, structured chmod/chown operations.

CONTRACTS: fix ``command`` strings are display/template material, never executed as
shell. Remediation reconstructs the intended operation here and validates every
argument, so only ``chmod <mode> <path>`` and ``chown <owner>[:<group>] <path>`` can
ever run. Anything else (sudo, service, capability, manual) raises UnsafeFix.
"""
import re

from sable.remediate.errors import UnsafeFix

_MODE = re.compile(r'^[0-7]{3,4}$')
_OWNER = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?$')
_PATH = re.compile(r'^/[^\s&|;`$()<>"\'\\]+$')


class Operation:
    """One validated filesystem operation: ('chmod', mode, path) / ('chown', spec, path)."""

    __slots__ = ('verb', 'argument', 'path')

    def __init__(self, verb, argument, path):
        self.verb = verb
        self.argument = argument
        self.path = path

    def __eq__(self, other):
        return isinstance(other, Operation) and (self.verb, self.argument, self.path) == (other.verb, other.argument, other.path)

    def __repr__(self):
        return f'Operation({self.verb!r}, {self.argument!r}, {self.path!r})'


def parse_operations(command):
    """Return the list of safe operations a fix command performs.

    Raises UnsafeFix if any segment is not a well-formed chmod/chown on an absolute
    path. The command may chain operations with ``&&`` (e.g. chown then chmod).
    """
    operations = []
    for segment in command.split('&&'):
        tokens = segment.split()
        if not tokens:
            continue
        verb = tokens[0]
        if verb not in ('chmod', 'chown') or len(tokens) != 3:
            raise UnsafeFix(f'not an applyable chmod/chown operation: {segment.strip()!r}')
        argument, path = tokens[1], tokens[2]
        if verb == 'chmod' and not _MODE.match(argument):
            raise UnsafeFix(f'invalid mode: {argument!r}')
        if verb == 'chown' and not _OWNER.match(argument):
            raise UnsafeFix(f'invalid owner spec: {argument!r}')
        if not _PATH.match(path):
            raise UnsafeFix(f'invalid or unsafe path: {path!r}')
        operations.append(Operation(verb, argument, path))
    if not operations:
        raise UnsafeFix('no operation found in fix command')
    return operations


def is_applyable(fix):
    """True only for chmod/chown fixes the planner marked script_and_apply (RM-04)."""
    return fix.get('execution') == 'script_and_apply' and fix.get('type') in ('chmod', 'chown')


def paths_of(fix):
    """The absolute paths a fix touches, parsed from its command."""
    return sorted({op.path for op in parse_operations(fix['command'])})
