# IAM Principal Condenser
# -----------------------
# This script navigates the present working directory to
# ingest "analysis/combined-gaad.json" to collect all IAM
# principals. For each user, it condenses all its policies
# (inline, attached, group inline, group attached) into a
# single place. It does the same for inline and attached
# policies of the roles. Only the latest versions of the
# policies are considered and all attached policies are
# also expanded. At the end, it produces a JSON file in
# the analysis directory with two large bucket keys of
# Users and Roles for further analysis with `jq`.

import json
import sys
import os

def get_policy(policy_arn, policies):
    for p in policies:
        if p['Arn'] == policy_arn:
            return p['PolicyVersionList'][0]
    return None

def condense_role(role, policies):
    r = role.copy()
    if not 'RolePolicyList' in r.keys():
        r['RolePolicyList'] = []
    if len(r['AttachedManagedPolicies']) > 0:
        for amp in r['AttachedManagedPolicies']:
            policy = get_policy(amp['PolicyArn'], policies).copy()
            policy['PolicyDocument'] = policy.pop('Document')
            r['RolePolicyList'].append(policy)
        r['AttachedManagedPolicies'] = []
    return r

def condense_user(user, groups_orig, policies):
    u = user.copy()
    if not 'UserPolicyList' in u.keys():
        u['UserPolicyList'] = []
    if len(u['AttachedManagedPolicies']) > 0:
        for amp in u['AttachedManagedPolicies']:
            policy = get_policy(amp['PolicyArn'], policies).copy()
            policy['PolicyDocument'] = policy.pop('Document')
            u['UserPolicyList'].append(policy)
        u['AttachedManagedPolicies'] = []
    if len(u['GroupList']) > 0:
        for g in u['GroupList']:
            garn = u['Arn'].split('user')[0] + 'group/' + g
            group = [i for i in groups_orig if i['Arn']==garn][0].copy()
            for amp in group['AttachedManagedPolicies']:
                policy = get_policy(amp['PolicyArn'], policies).copy()
                policy['PolicyDocument'] = policy.pop('Document')
                u['UserPolicyList'].append(policy)
            for policy in group['GroupPolicyList']:
                u['UserPolicyList'].append(policy)
    return u

def condense_principals(data):
    users = []
    roles = []
    for user in data['UserDetailList']:
        users.append(condense_user(user, data['GroupDetailList'], data['Policies']))
    for role in data['RoleDetailList']:
        roles.append(condense_role(role, data['Policies']))
    return roles, users

def main(data):
    roles, users = condense_principals(data)
    to_write = {'Users': users, 'Roles': roles}
    f = open('analysis/iam-condensed-principals.json', 'w')
    f.write(json.dumps(to_write))
    f.close()

if __name__ == '__main__':
    if not os.path.exists('./analysis/combined-gaad.json'):
        print('Usage: python3 iam-principal-condenser.py\nEnsure that analysis/combined-gaad.json in the current directory.')
        sys.exit(1)
    f = open('analysis/combined-gaad.json')
    data = json.loads(f.read())
    f.close()
    main(data)
