import copy
import json
from html.parser import HTMLParser
from pathlib import Path

import pytest
from sable.cli import main
from sable.contracts.validation import dumps, validate
from sable.fix.planner import finalize_results
from sable.redaction import redact
from sable.report.compare import compare_scans
from sable.report.html import render_html, write_report
from sable.report.terminal import terminal_summary

FIXTURES = Path(__file__).parent / 'fixtures'


def result():
    return finalize_results(json.loads((FIXTURES / 'results/weak3.analysis.json').read_text(encoding='utf-8')))


class Inspector(HTMLParser):
    def __init__(self):
        super().__init__(); self.headings=[]; self.heading=False; self.external=[]
    def handle_starttag(self, tag, attrs):
        self.heading = tag == 'h2'
        for key, value in attrs:
            if key in ('src','href') and value.startswith(('http:', 'https:', '//')):
                self.external.append(value)
    def handle_endtag(self, tag):
        if tag == 'h2': self.heading=False
    def handle_data(self, data):
        if self.heading: self.headings.append(data)


def test_sections_self_contained_and_json_export(tmp_path):
    paths = write_report(result(), tmp_path)
    html = paths['report.html'].read_text(encoding='utf-8')
    parser = Inspector(); parser.feed(html)
    assert {'Executive summary','Scan details','Ranked paths with breakdowns','Evidence','Fixes','Residual risk','No-writes certificate','Limitations'} <= set(parser.headings)
    assert not parser.external
    assert 'cytoscape' in html and 'step independence' in html
    data = json.loads(paths['results.json'].read_text(encoding='utf-8'))
    validate(data, 'results')
    assert dumps(data) == paths['results.json'].read_text(encoding='utf-8')


def test_output_redaction_and_script_injection(tmp_path):
    r = result()
    secret = 'test-secret-918273'
    payload = '</script><script>window.injected=true</script>'
    r['meta']['host'] = payload + secret
    r['fix_candidates'][0]['description'] = 'password=unlisted-secret'
    r['fixes'][0]['description'] = 'password=unlisted-secret'
    for path in write_report(r, tmp_path, secrets=[secret]).values():
        text = path.read_text(encoding='utf-8')
        assert secret not in text and 'unlisted-secret' not in text
    html = (tmp_path/'report.html').read_text(encoding='utf-8')
    assert payload not in html
    assert '\\u003c/script\\u003e' in html
    assert 'not_run' in html


def test_redaction_patterns():
    assert 'sensitive' not in str(redact({'x':'password="sensitive" token=sensitive Bearer sensitive mysql://user:sensitive@host'}))
    assert 'private-material' not in redact('-----BEGIN RSA PRIVATE KEY-----\nprivate-material\n-----END RSA PRIVATE KEY-----')
    assert '\x1b' not in redact('\x1b[31m')


def test_terminal_snapshot():
    expected = (FIXTURES/'terminal_weak3.txt').read_text(encoding='utf-8')
    assert terminal_summary(result()) == expected


def test_cis_and_kb_date_shown():
    r=result(); r['graph']['edges'][0]['cis']='1.2.3'; r['meta']['kb_date']='2026-11-14'
    html=render_html(r)
    assert 'CIS 1.2.3' in html and '2026-11-14' in html


def test_compare_structural_identity_and_score_changes():
    before=result(); after=copy.deepcopy(before)
    after['paths'].pop()
    after['paths'][0]['id']='new-path-id'
    after['paths'][0]['confidence']=.4
    diff=compare_scans(before,after)
    assert diff['removed']==['p-02'] and diff['added']==[]
    assert diff['confidence_changes'][0]['after']==.4


def test_cli_offline_end_to_end_and_override(tmp_path,capsys):
    config=tmp_path/'config.yaml'; config.write_text('path_cutoff: 1\n')
    path=FIXTURES/'results/weak3.analysis.json'
    assert main(['report',str(path),'--config',str(config),'--path-cutoff','2','--output',str(tmp_path/'report')])==0
    r=json.loads((tmp_path/'report/results.json').read_text(encoding='utf-8'))
    assert r['planning']['path_cutoff']==2
    assert 'Top three fixes' in capsys.readouterr().out
    assert main(['plan',str(path),'--output',str(tmp_path/'planned.json')])==0
    validate(json.loads((tmp_path/'planned.json').read_text(encoding='utf-8')),'results')


def test_invalid_input_leaves_no_report(tmp_path):
    with pytest.raises(Exception):
        write_report({'stage':'complete'},tmp_path/'report')
    assert not (tmp_path/'report').exists()


def test_exact_gap_is_displayed():
    from test_planning import six_paths
    r = json.loads((FIXTURES/'results/weak1.analysis.json').read_text(encoding='utf-8'))
    graph, paths, candidates = six_paths()
    r.update(graph=graph, paths=paths, fix_candidates=candidates,
             goals=[{'goal':p['goal'],'confidence':p['confidence']} for p in paths])
    html=render_html(finalize_results(r))
    assert 'Greedy: 3 fixes.' in html and 'Exact: 2 fixes.' in html and 'Gap: 1.' in html


def test_application_disclaimers_are_only_at_end():
    html = render_html(result())
    before, ending = html.split('<section id="limitations">', 1)
    ending = ending.split('</section>', 1)[0]
    assert '2 recommended fixes are available' in before
    assert 'No changes have been applied' not in before
    assert 'does not prove the host is secure' not in before
    assert 'do not execute commands' not in before
    assert 'this is not a passing certificate' not in html
    assert 'No changes have been applied' in ending
    assert 'does not prove the host is secure' in ending
    certificate = before.split('<section id="certificate">', 1)[1].split('</section>', 1)[0]
    assert 'Filesystem verification was not run.' in certificate
    assert 'class="notice"' not in certificate
    assert 'href="#limitations"' in certificate


@pytest.mark.parametrize('target,phrases', [
    ('weak1', ['read exposed credentials in /var/www/config.php', 'line 4']),
    ('weak2', ['modify /opt/backup.sh', 'writable by www-data', 'scheduled to run as root']),
    ('weak3', ['cap_setuid capability on /opt/python', 'reach root privileges', 'read password hashes from /etc/shadow']),
])
def test_path_explanations_use_recorded_evidence(target, phrases):
    r = finalize_results(json.loads((FIXTURES / f'results/{target}.analysis.json').read_text(encoding='utf-8')))
    html = render_html(r)
    path_section = html.split('<section id="paths">', 1)[1].split('</section>', 1)[0]
    for phrase in phrases:
        assert phrase in path_section
    if target == 'weak1':
        assert 'dbadmin' not in path_section


def test_empty_report_does_not_announce_recommended_fixes():
    r = finalize_results(json.loads((FIXTURES / 'results/hardened.analysis.json').read_text(encoding='utf-8')))
    html = render_html(r)
    assert 'No fixes were selected for this scan.' in html
    assert 'recommended fixes are available' not in html


def test_explanation_keeps_multistep_order_and_unknown_condition():
    from sable.report.explanations import report_explanations
    r = result()
    r['graph']['edges'][1]['src'] = 'root'
    r['graph']['edges'][0]['unknown_id'] = 'u-01'
    r['paths'] = [{'id':'chain', 'entry':'user:auditor', 'goal':'asset:/etc/shadow', 'edges':['e-01','e-02']}]
    explanation = report_explanations(r)['paths']['chain']
    assert '2-step route' in explanation['summary']
    assert explanation['steps'][0].startswith('If the missing evidence is confirmed')
    assert '/opt/python' in explanation['steps'][0]
    assert 'access to root privileges' in explanation['steps'][1]
    assert '/etc/shadow' in explanation['steps'][1]


def test_unrecognized_evidence_uses_graph_facts_without_inventing_mechanism():
    from sable.report.explanations import explain_step
    edge = {'src':'user:a', 'dst':'root', 'rule':'new_rule', 'evidence_ids':['ev-x'], 'breakdown':{'strength':'observed'}}
    evidence = {'ev-x': {'type':'new_type', 'data':{}}}
    text = explain_step(edge, evidence)
    assert 'new_rule' in text and 'ev-x' in text
    assert 'sudo' not in text and 'password' not in text


def test_explanations_are_redacted_and_escaped():
    r = result()
    r['evidence'][0]['data']['path'] = '/opt/<img src=x onerror=alert(1)>private-value'
    html = render_html(r, secrets=['private-value'])
    path_section = html.split('<section id="paths">', 1)[1].split('</section>', 1)[0]
    assert '<img' not in path_section and 'private-value' not in html
    assert '&lt;img' in path_section
