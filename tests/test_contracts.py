import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from sable.cli import main
from sable.contracts.validation import ContractError, dumps, load_schema, validate

FIXTURES = Path(__file__).parent / 'fixtures'


def read(relative):
    return json.loads((FIXTURES / relative).read_text(encoding='utf-8'))


@pytest.mark.parametrize('kind', ['snapshot', 'results'])
def test_schema_is_valid(kind):
    Draft202012Validator.check_schema(load_schema(kind))


@pytest.mark.parametrize('target', ['weak1', 'weak2', 'weak3', 'hardened'])
def test_all_handoffs(target):
    snapshot = read(f'snapshots/{target}.json')
    validate(snapshot, 'snapshot')
    for suffix in ['.analysis', '']:
        result = read(f'results/{target}{suffix}.json')
        validate(result, 'results', snapshot=snapshot)
        assert dumps(json.loads(dumps(result))) == dumps(result)


@pytest.mark.parametrize('mutation', [
    lambda x: x['evidence'][0].pop('source_cmd'),
    lambda x: x['evidence'][0]['data'].update(password='do-not-store'),
    lambda x: x['evidence'].append(copy.deepcopy(x['evidence'][0])),
    lambda x: x['graph']['edges'][0].update(evidence_ids=['absent']),
    lambda x: x['graph']['edges'][0].update(src='absent'),
    lambda x: x['paths'][0].update(edges=['absent']),
    lambda x: x['paths'][0].update(confidence=0.1),
    lambda x: x['fix_sets'].update(greedy=['absent']),
    lambda x: x['fix_candidates'][0].pop('rollback'),
    lambda x: x['fix_candidates'][0].update(type='sudo', execution='script_and_apply'),
    lambda x: x.update(residual=None),
    lambda x: x['no_writes'].update(status='passed'),
    lambda x: x['meta'].update(timestamp='yesterday'),
    lambda x: x.update(schema_version='2.0'),
    lambda x: x['residual']['paths'].append(copy.deepcopy(x['paths'][0])),
])
def test_rejects_broken_contracts(mutation):
    result = read('results/weak1.json')
    mutation(result)
    with pytest.raises(ContractError):
        validate(result, 'results')


def test_source_snapshot_is_preserved():
    result = read('results/weak1.json')
    result['meta']['host'] = 'different.example.test'
    with pytest.raises(ContractError, match='metadata'):
        validate(result, 'results', snapshot=read('snapshots/weak1.json'))


def test_analysis_cannot_claim_planning_is_complete():
    result = read('results/weak1.json')
    result['stage'] = 'analysis'
    with pytest.raises(ContractError):
        validate(result, 'results')


def test_cli_success(capsys):
    assert main(['validate', 'snapshot', str(FIXTURES / 'snapshots/hardened.json')]) == 0
    assert 'Valid snapshot' in capsys.readouterr().out


def test_cli_error_does_not_echo_payload(tmp_path, capsys):
    path = tmp_path / 'bad.json'
    path.write_text('{"secret":"never-echo-me"}', encoding='utf-8')
    with pytest.raises(SystemExit) as error:
        main(['validate', 'snapshot', str(path)])
    assert error.value.code == 2
    assert 'never-echo-me' not in capsys.readouterr().err
