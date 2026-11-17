"""Short report explanations derived only from supplied edges and evidence."""


def state_label(identifier):
    if identifier == 'root':
        return 'root privileges'
    if identifier.startswith('user:'):
        return f"the {identifier[5:]} account"
    if identifier.startswith('asset:'):
        return f"the file {identifier[6:]}"
    if identifier.startswith('cred:'):
        return f"the credentials identified as {identifier[5:]}"
    return identifier


def explain_step(edge, evidence):
    records = [evidence[eid] for eid in edge['evidence_ids']]
    source, target = state_label(edge['src']), state_label(edge['dst'])
    prefix = f'An attacker with access to {source} could '
    if edge.get('unknown_id') or edge['breakdown']['strength'] == 'unknown':
        prefix = f'If the missing evidence is confirmed, an attacker with access to {source} could '
    for record in records:
        data, kind = record['data'], record['type']
        if kind == 'capability' and any('cap_setuid' in cap for cap in data['capabilities']):
            return prefix + f"use the cap_setuid capability on {data['path']} to change the process user identity and reach {target}."
        if kind == 'scheduled_job' and data['writable_by']:
            return prefix + f"modify {data['script_path']}, which is writable by {', '.join(data['writable_by'])} and scheduled to run as {data['run_as']}, to reach {target}."
        if kind == 'credential_location':
            return prefix + f"read exposed credentials in {data['path']} at line {data['line']} to access {target}."
        if kind == 'file_permission' and edge['dst'].startswith('asset:'):
            contents = 'password hashes' if data['path'] == '/etc/shadow' else 'file contents'
            return prefix + f"read {contents} from {data['path']} through the file permissions recorded as {data['mode']}."
        if kind == 'suid_binary':
            flags = '/'.join(flag for flag in ('SUID', 'SGID') if data[flag.lower()])
            if flags:
                return prefix + f"use {data['path']} with its {flags} permissions to reach {target}, as identified by rule {edge['rule']}."
        if kind == 'sudo_rule':
            commands = ', '.join(data['commands'])
            password = ' without a password' if data['nopasswd'] else ''
            return prefix + f"run {commands} as {data['runas']}{password} under the recorded sudo rule to reach {target}."
        if kind == 'package':
            return prefix + f"use the weakness matched by rule {edge['rule']} in {data['name']} {data['version']} to reach {target}."
    return f"The graph identifies a route from {source} to {target} under rule {edge['rule']}, supported by evidence {', '.join(edge['evidence_ids'])}."


def report_explanations(results):
    edges = {edge['id']: edge for edge in results['graph']['edges']}
    evidence = {item['id']: item for item in results['evidence']}
    paths = {}
    for path in results['paths'] + results['residual']['paths']:
        paths[path['id']] = {
            'summary': f"This {len(path['edges'])}-step route connects {state_label(path['entry'])} to {state_label(path['goal'])}.",
            'steps': [explain_step(edges[eid], evidence) for eid in path['edges']],
        }
    fixes = {}
    for fix in results['fixes']:
        affected = [path for path in results['paths'] if set(path['edges']) & set(fix['breaks_edges'])]
        destinations = sorted({state_label(path['goal']) for path in affected})
        count = len(affected)
        fixes[fix['id']] = (f"This fix targets {count} reported {'path' if count == 1 else 'paths'} to "
                            + ', '.join(destinations) + '.') if affected else 'This fix has no matching path in the supplied results.'
    goals = {}
    for goal in results['goals']:
        count = sum(path['goal'] == goal['goal'] for path in results['paths'])
        goals[goal['goal']] = f"{count} reported {'route leads' if count == 1 else 'routes lead'} to {state_label(goal['goal'])}."
    return {'paths': paths, 'fixes': fixes, 'goals': goals}
