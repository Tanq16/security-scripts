# IAM Permission Condenser
# ------------------------
# This script navigates the present working directory to
# ingest "analysis/iam-condensed-principals-gaad.json" to
# collect all condensed IAM principals. For each princpal,
# it condenses all the permissions into strings with format
# "<action> || <resource>", where actions are always fully
# expanded, but resources could have wildcards (*) as well.
# At the end, it produces a JSON file in the analysis
# directory with two large bucket keys of Users and Roles
# with their permissions for further analysis with `jq`.

import requests
import json
import fnmatch
import os
import sys

def gen_actions_dump():
    data = json.loads(str(requests.get('https://awspolicygen.s3.amazonaws.com/js/policies.js').content, encoding='utf-8').split('=')[1])
    actions = []
    for i in data['serviceMap']:
        prefix = data['serviceMap'][i]['StringPrefix']
        for j in data['serviceMap'][i]['Actions']:
            actions.append(prefix + ':' + j)
    return actions

def evaluate_policies(policies, actions_dump):
    allowed_actions = set()
    denied_actions = set()
    # allowed_actions_notresource = set()
    # denied_actions_notresource = set()
    conditional_denys = []
    conditional_allows = []
    has_allow_condition = False
    has_deny_condition = False

    for pol in policies:
        policy = pol['PolicyDocument']
        statements = policy['Statement'] if type(policy['Statement'])==list else [policy['Statement']]
        for statement in statements:
            if statement['Effect'] == 'Allow':
                actions, resources = [], []
                if 'Action' in statement:
                    actions_temp = statement['Action'] if type(statement['Action'])==list else [statement['Action']]
                    for act in actions_temp:
                        for outer_act in actions_dump:
                            if fnmatch.fnmatch(outer_act, act):
                                actions.append(outer_act)
                elif "NotAction" in statement:
                    actions_temp = statement['NotAction'] if type(statement['NotAction'])==list else [statement['NotAction']]
                    for act in actions_temp:
                        for outer_act in actions_dump:
                            if not fnmatch.fnmatch(outer_act, act):
                                actions.append(outer_act)
                if 'Resource' in statement:
                    resources = statement['Resource'] if type(statement['Resource'])==list else [statement['Resource']]
                elif 'NotResource' in statement:
                    resources_temp = statement['NotResource'] if type(statement['NotResource'])==list else [statement['NotResource']]
                    resources = ['-' + i for i in resources_temp]
                if 'Condition' in statement:
                    has_allow_condition = True
                    if not pol in conditional_allows:
                        conditional_allows.append(pol)
                for i in actions:
                    for j in resources:
                        allowed_actions.add((i, j))
                        # if j[0] == '-':
                        #     allowed_actions_notresource.add((i, j))
                        # else:
                        #     allowed_actions.add((i, j))
            elif statement['Effect'] == 'Deny':
                actions, resources = [], []
                if 'Action' in statement:
                    actions_temp = statement['Action'] if type(statement['Action'])==list else [statement['Action']]
                    for act in actions_temp:
                        for outer_act in actions_dump:
                            if fnmatch.fnmatch(outer_act, act):
                                actions.append(outer_act)
                elif "NotAction" in statement:
                    actions_temp = statement['NotAction'] if type(statement['NotAction'])==list else [statement['NotAction']]
                    for act in actions_temp:
                        for outer_act in actions_dump:
                            if not fnmatch.fnmatch(outer_act, act):
                                actions.append(outer_act)
                if 'Resource' in statement:
                    resources = statement['Resource'] if type(statement['Resource'])==list else [statement['Resource']]
                elif 'NotResource' in statement:
                    resources_temp = statement['NotResource'] if type(statement['NotResource'])==list else [statement['NotResource']]
                    resources = ['-' + i for i in resources_temp]
                if 'Condition' in statement:
                    has_deny_condition = True
                    if not pol in conditional_denys:
                        conditional_denys.append(pol)
                for i in actions:
                    for j in resources:
                        denied_actions.add((i, j))
                        # if j[0] == '-':
                        #     denied_actions_notresource.add((i, j))
                        # else:
                        #     denied_actions.add((i, j))

    ald_actions = [i + ' || ' + j for (i,j) in sorted(allowed_actions)]
    dnd_actions = [i + ' || ' + j for (i,j) in sorted(denied_actions)]

    return ald_actions, dnd_actions, has_allow_condition, has_deny_condition, list(conditional_allows), list(conditional_denys)

def main(data):
    actions_dump = gen_actions_dump()
    users, roles = data['Users'], data['Roles']
    print(len(users), len(roles))
    condensed_permissions = {'Users': [], 'Roles': []}
    for i in users:
        print(i['UserName'])
        allowed_actions, denied_actions, acond, dcond, acondpols, dcondpols = evaluate_policies(i['UserPolicyList'], actions_dump)
        condensed_permissions['Users'].append({'User': i['Arn'], 'UserName': i['UserName'], 'Allowed': allowed_actions, 'Denied': denied_actions, 'Allow Conditions': acond, 'Deny Conditions': dcond, 'Allow Condition Policies': acondpols, 'Deny Condition Policies': dcondpols})
    for i in roles:
        print(i['RoleName'])
        allowed_actions, denied_actions, acond, dcond, acondpols, dcondpols = evaluate_policies(i['RolePolicyList'], actions_dump)
        condensed_permissions['Roles'].append({'Role': i['Arn'], 'RoleName': i['RoleName'], 'Allowed': allowed_actions, 'Denied': denied_actions, 'Allow Conditions': acond, 'Deny Conditions': dcond, 'Allow Condition Policies': acondpols, 'Deny Condition Policies': dcondpols})
    f = open('analysis/iam-condensed-permissions.json', 'w')
    f.write(json.dumps(condensed_permissions))
    f.close()

if __name__ == '__main__':
    if not os.path.exists('./analysis/iam-condensed-principals.json'):
        print('Usage: python3 iam-permission-condenser.py\nEnsure that analysis/iam-condensed-principals.json in the current directory.')
        sys.exit(1)
    f = open('analysis/iam-condensed-principals.json')
    data = json.loads(f.read())
    f.close()
    main(data)
