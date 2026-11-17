"""Self-contained Jinja2 HTML and schema-validated JSON export."""
from importlib.resources import files
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from sable.contracts.validation import ContractError, dumps, validate
from sable.redaction import redact
from sable.report.terminal import terminal_summary
from sable.report.explanations import report_explanations


def render_html(results, secrets=()):
    validate(results, 'results')
    if results['stage'] != 'complete':
        raise ContractError('Report requires completed planning results')
    r = redact(results, secrets)
    root = files('sable.report')
    env = Environment(loader=FileSystemLoader(str(root.joinpath('templates'))),
                      autoescape=select_autoescape(['html']), undefined=StrictUndefined)
    edges = {e['id']: e for e in r['graph']['edges']}
    planning = r.get('planning')
    curve = planning['risk_curve'] if planning else []
    max_count = max((p['fix_count'] for p in curve), default=1) or 1
    points = ' '.join(f"{40+520*p['fix_count']/max_count:.2f},{170-140*p['percent']/100:.2f}" for p in curve)
    return env.get_template('report.html').render(r=r, edges=edges, explanations=report_explanations(r),
        paths=sorted(r['paths'], key=lambda p: (-p['confidence'], p['id'])),
        planning=planning, curve_points=points,
        cytoscape=root.joinpath('vendor/cytoscape.min.js').read_text(encoding='utf-8'),
        interaction=root.joinpath('templates/what_if.js').read_text(encoding='utf-8'))


def write_report(results, output_dir, secrets=()):
    """Write report.html, results.json and summary.txt; return their paths."""
    clean = redact(results, secrets)
    validate(clean, 'results')
    html = render_html(clean)
    summary = terminal_summary(clean)
    payloads = {'report.html': html, 'results.json': dumps(clean), 'summary.txt': summary}
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, contents in payloads.items():
        (output_dir / name).write_text(contents, encoding='utf-8')
    return {name: output_dir / name for name in payloads}
