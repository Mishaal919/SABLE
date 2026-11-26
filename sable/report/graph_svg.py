"""AG-07: a static, self-contained SVG of the top attack paths for the report.

Complements the interactive Cytoscape view with a print-friendly diagram that renders
without JavaScript. Pure function over completed results, no external assets. All
node/edge text is XML-escaped; the SVG is embedded inline (the report CSP allows it).
"""
from html import escape

# Node fill by kind; all use white text for contrast.
_KIND_FILL = {'root': '#8c2818', 'asset': '#755311', 'credential': '#14685b', 'privilege': '#33506a'}
_BAND_FILL = {'High': '#c0392b', 'Medium': '#ac7b13', 'Low': '#526473'}


def _kind(node_id):
    if node_id == 'root':
        return 'root'
    if node_id.startswith('asset:'):
        return 'asset'
    if node_id.startswith('cred:'):
        return 'credential'
    return 'privilege'


def _short(text, maxlen=22):
    """Shorten a node id / rule name to fit a box, keeping the meaningful tail."""
    if len(text) <= maxlen:
        return text
    prefix, sep, rest = text.partition(':')
    if sep and '/' in rest:
        candidate = f'{prefix}:…/{rest.rsplit("/", 1)[-1]}'
        if len(candidate) <= maxlen:
            return candidate
    return text[:maxlen - 1] + '…'


def top_paths_svg(results, limit=5):
    """Return an inline SVG string for the top ``limit`` paths, or '' if there are none."""
    paths = sorted(results.get('paths', []), key=lambda p: (-p['confidence'], p['id']))[:limit]
    edges = {e['id']: e for e in results['graph']['edges']}
    if not paths:
        return ''

    nw, nh, gap, row_h, left, pad, top = 150, 30, 56, 62, 150, 16, 36
    max_nodes = max(len(p['edges']) + 1 for p in paths)
    width = left + max_nodes * nw + max(max_nodes - 1, 0) * gap + pad
    height = top + len(paths) * row_h + pad

    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Top {len(paths)} attack paths" '
        f'xmlns="http://www.w3.org/2000/svg" font-family="system-ui,sans-serif">',
        '<defs><marker id="sable-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
        '<path d="M0 0 L8 4 L0 8 z" fill="#526473"/></marker></defs>',
        '<text x="0" y="20" font-size="13" font-weight="700" fill="#192c3c">Top attack paths</text>',
    ]
    for index, path in enumerate(paths):
        y = top + index * row_h
        cy = y + nh / 2
        band = path.get('band', 'Low')
        parts.append(f'<rect x="0" y="{y + 3:.0f}" width="104" height="{nh - 6:.0f}" rx="11" '
                     f'fill="{_BAND_FILL.get(band, "#526473")}"/>')
        parts.append(f'<text x="52" y="{cy + 4:.0f}" font-size="11" fill="#fff" text-anchor="middle">'
                     f'{escape(band)} {path["confidence"]:.2f}</text>')
        nodes = [path['entry']] + [edges[eid]['dst'] for eid in path['edges']]
        for j, node in enumerate(nodes):
            x = left + j * (nw + gap)
            parts.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{nw}" height="{nh}" rx="5" '
                         f'fill="{_KIND_FILL[_kind(node)]}"/>')
            parts.append(f'<text x="{x + nw / 2:.0f}" y="{cy + 4:.0f}" font-size="11" fill="#fff" '
                         f'text-anchor="middle">{escape(_short(node))}</text>')
            if j < len(nodes) - 1:
                ax1, ax2 = x + nw, x + nw + gap
                parts.append(f'<line x1="{ax1:.0f}" y1="{cy:.0f}" x2="{ax2 - 3:.0f}" y2="{cy:.0f}" '
                             f'stroke="#526473" stroke-width="1.5" marker-end="url(#sable-arrow)"/>')
                parts.append(f'<text x="{(ax1 + ax2) / 2:.0f}" y="{y - 3:.0f}" font-size="9" fill="#526473" '
                             f'text-anchor="middle">{escape(_short(edges[path["edges"][j]]["rule"], 18))}</text>')
    parts.append('</svg>')
    return ''.join(parts)
