"""AG-07: static top-paths SVG for the report."""
import json
import pathlib

from sable.report.graph_svg import top_paths_svg
from sable.report.html import render_html

RESULTS = pathlib.Path(__file__).resolve().parent / 'fixtures' / 'results'


def _results(name):
    return json.loads((RESULTS / name).read_text(encoding='utf-8'))


def test_svg_renders_top_paths():
    svg = top_paths_svg(_results('weak3.json'))
    assert svg.startswith('<svg') and svg.endswith('</svg>')
    assert 'Top attack paths' in svg
    assert 'viewBox' in svg and 'xmlns="http://www.w3.org/2000/svg"' in svg
    # weak3 reaches root and the shadow asset from the scan user.
    assert '>root<' in svg
    assert 'asset:' in svg  # shortened /etc/shadow asset node
    assert 'High' in svg


def test_svg_empty_when_no_paths():
    hardened = _results('hardened.json')
    assert hardened['paths'] == []
    assert top_paths_svg(hardened) == ''


def test_svg_respects_limit():
    results = _results('weak3.json')
    # Duplicate paths to exceed the limit; only `limit` rows are drawn.
    results['paths'] = results['paths'] * 4
    svg = top_paths_svg(results, limit=2)
    # Two band pills (rounded rects at x="0") for two rows.
    assert svg.count('<rect x="0"') == 2


def test_svg_escapes_text():
    results = _results('weak3.json')
    # Inject a node id with XML-special characters and point a path at it.
    results['graph']['nodes'].append({'id': 'asset:/x&<b>', 'kind': 'asset'})
    results['graph']['edges'][0]['dst'] = 'asset:/x&<b>'
    results['paths'][0]['goal'] = 'asset:/x&<b>'
    svg = top_paths_svg(results)
    assert '&amp;' in svg        # & escaped
    assert '&lt;b&gt;' in svg    # <b> escaped
    assert '<b>' not in svg      # no raw markup injected


def test_report_embeds_static_svg():
    html = render_html(_results('weak3.json'))
    assert 'Top attack paths' in html
    assert '<svg' in html and 'paths-figure' in html
