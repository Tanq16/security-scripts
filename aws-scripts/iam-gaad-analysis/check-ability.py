# IAM Check Ability
# -----------------
# This script navigates the present working directory to
# find the analysis folder and the combined-gaad.json file
# using which it checks the permissions of all principals
# against the list of provided actions and returns all the
# ARNs of principals who can perform those actions.

import fnmatch
import json
import sys

def check_action_in_policy(action, policies):
    allowed = False
    for i in policies:
        if not i["Action"] == None and action in i["Action"] and i["Effect"] == "Allow":
            allowed = True
            break
        # elif not i["NotAction"] == None and not action in i["NotAction"] and i["Effect"] == "Allow":
        #     allowed = True
        #     break
    return allowed

def check_user_permissions(actionlist, user, data, groups):
    policies = []
    if "AttachedManagedPolicies" in user.keys():
        for i in user["AttachedManagedPolicies"]:
            for x in data["Policies"]:
                if x["Arn"] == i["PolicyArn"]:
                    policies += x["PolicyDocument"]["Statement"]
    if "UserPolicyList" in user.keys():
        for i in user["UserPolicyList"]:
            policies += i["PolicyDocument"]["Statement"]
    for grp in user["GroupList"]:
        group = [x for x in groups if x["Arn"] == grp][0]
        if "AttachedManagedPolicies" in group.keys():
            for i in group["AttachedManagedPolicies"]:
                for x in data["Policies"]:
                    if x["Arn"] == i["PolicyArn"]:
                        policies += x["PolicyDocument"]["Statement"]
        if "GroupPolicyList" in group.keys():
            for i in group["GroupPolicyList"]:
                policies += i["PolicyDocument"]["Statement"]
    allowed = True
    for i in actionlist:
        allowed = check_action_in_policy(i, policies)
        if not allowed:
            break
    return allowed

def check_role_permissions(actionlist, role, data):
    policies = []
    if "AttachedManagedPolicies" in role.keys():
        for i in role["AttachedManagedPolicies"]:
            for x in data["Policies"]:
                if x["Arn"] == i["PolicyArn"]:
                    policies += x["PolicyDocument"]["Statement"]
    if "RolePolicyList" in role.keys():
        for i in role["RolePolicyList"]:
            policies += i["PolicyDocument"]["Statement"]
    allowed = True
    for i in actionlist:
        allowed = check_action_in_policy(i, policies)
        if not allowed:
            break
    return allowed

def action_allowed(actionlist, data):
    principals = []
    for i in data["RoleDetailList"]:
        cando = check_role_permissions(actionlist, i, data)
        if cando:
            principals.append(i["Arn"])
    for i in data["UserDetailList"]:
        groups = []
        cando = check_user_permissions(actionlist, i, data, groups)
        if cando:
            principals.append(i["Arn"])
    return principals

def main(actionstring):
    f = open("analysis/combined-gaad.json")
    ingested_data = json.loads(f.read())
    f.close()

    actions_to_check = actionstring.split(",")

    principals = action_allowed(actions_to_check, ingested_data)
    for i in principals:
        print(i)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 check-ability.py action_list_without_spaces_just_commas\nEnsure that analysis/combined-gaad.json in the current directory.')
        sys.exit(1)
    main(sys.argv[1])
