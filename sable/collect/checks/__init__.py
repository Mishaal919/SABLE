"""EC-03..EC-12 evidence parsers.

Each module exposes pure functions that turn command output into evidence
dictionaries (``type``/``data``/``source_cmd``/``strength``) with no ``id`` and no
SSH dependency, so they are unit-tested with hand-made strings. The collector runs
the allow-listed commands and feeds their output to these parsers.
"""
