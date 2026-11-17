"""KB-04: load and validate every YAML catalogue file in a knowledge-base folder."""
import json
from importlib.resources import files
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from sable.contracts.validation import ContractError
from sable.kb.versions import parse_version

ATTACK_TECHNIQUES = frozenset({
    'T1003.008', 'T1053.003', 'T1068', 'T1078.003', 'T1098', 'T1543.002',
    'T1548', 'T1548.001', 'T1548.003', 'T1552.001', 'T1552.004',
})


class KnowledgeBaseError(ContractError):
    """A KB file is unreadable or invalid; the message names the file and field."""


def _schema():
    return json.loads(files('sable.kb').joinpath('kb.schema.json').read_text(encoding='utf-8'))


def _data_files(directory):
    root = files('sable.kb').joinpath('data') if directory is None else Path(directory)
    if not root.is_dir():
        raise KnowledgeBaseError(f'{root}: knowledge-base folder not found')
    return sorted((item for item in root.iterdir() if item.name.endswith(('.yaml', '.yml'))), key=lambda item: item.name)


def _fail(name, location, message):
    raise KnowledgeBaseError(f'{name}: {location or "<root>"}: {message}')


def load_kb(directory=None):
    """Return {'meta', 'binaries', 'cves', 'rules'} merged from every YAML file.

    directory defaults to the packaged sable/kb/data. New files dropped into the
    folder are used without code changes. Errors name the file and field.
    """
    validator = Draft202012Validator(_schema())
    kb = {'meta': None, 'binaries': {}, 'cves': {}, 'rules': {}}
    origin = {}
    for item in _data_files(directory):
        name = item.name
        try:
            document = yaml.safe_load(item.read_text(encoding='utf-8'))
        except (OSError, UnicodeError) as exc:
            raise KnowledgeBaseError(f'{name}: cannot be read') from exc
        except yaml.YAMLError as exc:
            mark = getattr(exc, 'problem_mark', None)
            where = f'line {mark.line + 1}' if mark else 'YAML'
            raise KnowledgeBaseError(f'{name}: {where}: invalid YAML') from exc
        if document is None:
            continue
        errors = sorted(validator.iter_errors(document), key=lambda e: list(map(str, e.absolute_path)))
        if errors:
            error = errors[0]
            _fail(name, '/'.join(str(p) for p in error.absolute_path), error.message)
        if 'meta' in document:
            if kb['meta'] is not None:
                _fail(name, 'meta', f"duplicate catalogue metadata (already in {origin['meta']})")
            kb['meta'], origin['meta'] = document['meta'], name
        for section, key in (('binaries', 'name'), ('cves', 'id'), ('rules', 'id')):
            for index, entry in enumerate(document.get(section, [])):
                identifier = entry[key]
                if identifier in kb[section]:
                    _fail(name, f'{section}/{index}/{key}', f"duplicate {identifier!r} (already in {origin[(section, identifier)]})")
                kb[section][identifier] = entry
                origin[(section, identifier)] = name
                _check_entry(name, section, index, entry)
    if kb['meta'] is None:
        raise KnowledgeBaseError('knowledge base: no file provides meta (version and date)')
    return kb


def _check_entry(name, section, index, entry):
    if section == 'cves':
        for position, affected in enumerate(entry['affected']):
            for field in ('introduced', 'fixed'):
                if field in affected:
                    try:
                        parse_version(affected[field])
                    except ValueError:
                        _fail(name, f'cves/{index}/affected/{position}/{field}', 'invalid Debian package version')
    if section == 'rules':
        if entry['attack'] not in ATTACK_TECHNIQUES:
            _fail(name, f'rules/{index}/attack', f"{entry['attack']} is not in the accepted ATT&CK technique list")
        if entry['kind'] != 'match' and any(k in entry for k in ('when', 'actors', 'target', 'binary', 'evidence_type')):
            _fail(name, f'rules/{index}/kind', f"{entry['kind']} rules are built in code and take no match fields")
