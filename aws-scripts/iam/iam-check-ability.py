# IAM Check Ability
# -----------------
# This script navigates the present working directory to
# ingest some analysis JSON files and collects all IAM
# condensed principals and permissions. For a given action
# and resource pair (provide resource in ARN format), it
# checks which principals throughout the combined accounts
# can perform those actions. For non-AssumeRole actions,
# it gives a list of entities that can perform the action,
# along with the type of allow and whether there is a need
# to check for conditions in the associated policies. For
# AssumeRole actions, it just returns the principals that
# are allowed to assume.

import fnmatch
import json
import sys
import os

def find_assumers(entities, assumed):
    trusted = []
    for stmt in assumed['AssumeRolePolicyDocument']['Statement']:
        if stmt['Effect'] == 'Allow' and stmt['Action'] == 'sts:AssumeRole' and 'AWS' in stmt['Principal']:
            ent = stmt['Principal']['AWS'] if type(stmt['Principal']['AWS'])==list else [stmt['Principal']['AWS']]
            for i in ent:
                if i[-4:] == 'root':
                    for x in entities:
                        if x[0].startswith(i[:-4]):
                            trusted.append(x[0])
                elif i.startswith('arn'):
                    if not i in trusted:
                        trusted.append(i)
    return trusted

def can_perform(action, resource, entity):
    result = [False, "implicit deny", "no conditions"]
    for permission in entity['Allowed']:
        act, res = permission.split(" || ")
        if act == action and not res[0] == '-':
            if fnmatch.fnmatch(resource, res):
                result = [True, "explicit allow", "no conditions"]
                break
    if result[0] == False:
        all_done = False
        count = 0
        for permission in entity['Allowed']:
            act, res = permission.split(" || ")
            if act == action and res[0] == '-':
                count += 1
                if fnmatch.fnmatch(resource, res[1:]):
                    result = [False, "implicit notresource deny", "no conditions"]
                    all_done = True
                    break
        if not all_done and count > 0:
            result = [True, "explicit notresource allow", "no conditions"]
    if result[0] == True:
        for permission in entity['Denied']:
            act, res = permission.split(" || ")
            if act == action and fnmatch.fnmatch(resource, res):
                result = [False, "explicit deny", "no condition"]
                break
    if result[0] == True:
        found = False
        count = 0
        for permission in entity['Allowed']:
            act, res = permission.split(" || ")
            if act == action and res[0] == '-':
                count += 1
                if fnmatch.fnmatch(resource, res[1:]):
                    found = True
                    continue
        if not found and count > 0:
            result = [False, "explicit notresource deny", "no conditions"]
    if result[0] == False and not result[1] == "implicit deny" and entity['Deny Conditions']:
        result[2] = "check conditions"
    if result[0] == True and entity['Allow Conditions']:
        result[2] = "check conditions"
    return result

def find_performers(action, resource, condensed_permissions):
    entities = []
    for i in condensed_permissions['Users']:
        result = can_perform(action, resource, i)
        if result[0]:
            entities.append([i['User'], result[1], result[2]])
        elif not result[0] and result[2] == "check conditions":
            entities.append([i['User'], result[1], result[2]])
    for i in condensed_permissions['Roles']:
        result = can_perform(action, resource, i)
        if result[0]:
            entities.append([i['Role'], result[1], result[2]])
        elif not result[0] and result[2] == "check conditions":
            entities.append([i['Role'], result[1], result[2]])
    return entities

def main(action, resource):
    f = open('analysis/iam-condensed-permissions.json')
    condensed_permissions = json.loads(f.read())
    f.close()
    f = open('analysis/iam-condensed-principals.json')
    condensed_principals = json.loads(f.read())
    f.close()
    if action == 'sts:AssumeRole':
        entities = find_performers(action, resource, condensed_permissions)
        entities = find_assumers(entities, [i for i in condensed_principals['Roles'] if i['Arn']==resource][0])
    else:
        entities = find_performers(action, resource, condensed_permissions)
    for i in entities:
        print(i)

if __name__ == '__main__':
    if not os.path.exists('./analysis/iam-condensed-principals.json') or not os.path.exists('./analysis/iam-condensed-permissions.json'):
        print('Usage: python3 iam-check-ability.py\nEnsure that analysis/iam-condensed-principals.json and analysis/iam-condensed-permissions.json are in the current directory.')
        sys.exit(1)
    if len(sys.argv) < 3:
        print('Usage: python3 iam-check-ability.py <action> <resource>')
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
