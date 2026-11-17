"""RE-04 terminal summary; returns text without writing to global stdout."""
from sable.redaction import redact


def terminal_summary(results, secrets=()):
    r = redact(results, secrets)
    def cell(value, width):
        text = ' '.join(str(value).split())
        return (text if len(text) <= width else text[:width-3] + '...').ljust(width)
    lines = [f"SABLE | {cell(r['meta']['host'], 40).rstrip()} | mode: {r['meta']['mode']}",
             'Top paths', f"{'Path':<20} {'Confidence':<12} {'Band':<8} Goal"]
    for p in sorted(r['paths'], key=lambda p: (-p['confidence'], p['id']))[:5]:
        lines.append(f"{cell(p['id'], 20)} {p['confidence']:<12.3f} {p['band']:<8} {cell(p['goal'], 40).rstrip()}")
    if not r['paths']:
        lines.append('No paths found in the supplied graph.')
    lines += ['Top three fixes', f"{'Fix':<20} {'Risk removed':<14} Recommendation"]
    for f in r['fixes'][:3]:
        lines.append(f"{cell(f['id'], 20)} {f['risk_removed']:<14.3f} {cell(f['command'], 70).rstrip()}")
    if not r['fixes']:
        lines.append('No fix selected.')
    lines += [f"Residual paths: {len(r['residual']['paths'])}; missing checks: {len(r['missing'])}",
              f"No-writes certificate: {r['no_writes']['status']}",
              'Predictions only; fixes have not been applied.']
    return '\n'.join(lines) + '\n'
