"""Regenerate result fixtures from the committed snapshots with the real analyzer.

Run from the project root after changing the KB, graph builder or scoring:

    python tests/fixtures/regenerate.py

Writes results/<target>.analysis.json (analyze), results/<target>.json
(finalize_results + compute_voi) and terminal_weak3.txt. Review the diff before
committing: changed fixtures change what the planner/report tests assert.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sable.contracts.validation import dumps, validate  # noqa: E402
from sable.fix.planner import finalize_results  # noqa: E402
from sable.graph.build import analyze  # noqa: E402
from sable.report.terminal import terminal_summary  # noqa: E402
from sable.score.voi import compute_voi  # noqa: E402

FIXTURES = Path(__file__).resolve().parent
# weak2's planted path starts at www-data, so it must be enabled as an entry (AG-02).
TARGETS = {'weak1': {}, 'weak2': {'extra_entry_points': ['www-data']}, 'weak3': {}, 'hardened': {}}


def main():
    for target, config in TARGETS.items():
        snapshot = json.loads((FIXTURES / f'snapshots/{target}.json').read_text(encoding='utf-8'))
        analysis = analyze(snapshot, config)
        complete = finalize_results(analysis)
        complete['voi'] = compute_voi(complete)
        validate(complete, 'results', snapshot=snapshot)
        (FIXTURES / f'results/{target}.analysis.json').write_text(dumps(analysis), encoding='utf-8')
        (FIXTURES / f'results/{target}.json').write_text(dumps(complete), encoding='utf-8')
        if target == 'weak3':
            (FIXTURES / 'terminal_weak3.txt').write_text(terminal_summary(finalize_results(analysis)), encoding='utf-8')
        print(f'{target}: {len(analysis["graph"]["edges"])} edges, {len(analysis["paths"])} paths')


if __name__ == '__main__':
    main()
