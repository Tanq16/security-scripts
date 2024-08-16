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
        if not i["Action"] == None and any(action.upper() == x.upper() for x in i["Action"]) and i["Effect"] == "Allow":
            allowed = True
            break
        elif not i["NotAction"] == None and not any(action.upper() == x.upper() for x in i["NotAction"]) and i["Effect"] == "Allow":
            allowed = True
            break
    return allowed

def check_user_permissions(actionlist, user, data):
    policies = []
    if "AttachedManagedPolicies" in user.keys():
        for i in user["AttachedManagedPolicies"]:
            for x in data["Policies"]:
                if x["Arn"] == i["PolicyArn"]:
                    policies += x["PolicyDocument"]["Statement"]
    if "UserPolicyList" in user.keys():
        for i in user["UserPolicyList"]:
            for x in data["Policies"]:
                if x["Arn"] == i["Arn"]:
                    policies += x["PolicyDocument"]["Statement"]
    for grp in user["GroupList"]:
        group = [x for x in data["GroupDetailList"] if x["Arn"] == grp][0]
        if "AttachedManagedPolicies" in group.keys():
            for i in group["AttachedManagedPolicies"]:
                for x in data["Policies"]:
                    if x["Arn"] == i["PolicyArn"]:
                        policies += x["PolicyDocument"]["Statement"]
        if "GroupPolicyList" in group.keys():
            for i in group["GroupPolicyList"]:
                for x in data["Policies"]:
                    if x["Arn"] == i["Arn"]:
                        policies += x["PolicyDocument"]["Statement"]
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
            for x in data["Policies"]:
                if x["Arn"] == i["Arn"]:
                    policies += x["PolicyDocument"]["Statement"]
    allowed = True
    for i in actionlist:
        allowed = check_action_in_policy(i, policies)
        if not allowed:
            break
    return allowed

def action_allowed(actionlist, data, excludeps):
    principals = []
    for i in data["RoleDetailList"]:
        init = False
        for j in excludeps:
            if j in i["Arn"]:
                init = True
                break
        if init:
            continue
        cando = check_role_permissions(actionlist, i, data)
        if cando:
            principals.append(i["Arn"])
    for i in data["UserDetailList"]:
        if i["Arn"] in excludeps:
            continue
        cando = check_user_permissions(actionlist, i, data)
        if cando:
            principals.append(i["Arn"])
    return principals

def main(actionstring, excludeps):
    f = open("analysis/combined-gaad.json")
    ingested_data = json.loads(f.read())
    f.close()

    if not actionstring == "privesc":
        actions_to_check = actionstring.split(",")
        principals = action_allowed(actions_to_check, ingested_data, excludeps)
        for i in principals:
            print(i)
        return

    privescs = ["iam:CreatePolicyVersion","ec2:RunInstances,iam:PassRole","iam:CreateAccessKey","cloudformation:CreateChangeSet,cloudformation:ExecuteChangeSet","lambda:CreateFunction,lambda:InvokeFunction,iam:PassRole","iam:AttachUserPolicy"]

    print("| Privesc Vector | Principal |\n| --- | --- |")
    for i in privescs:
        actions_to_check = i.split(",")
        principals = action_allowed(actions_to_check, ingested_data, excludeps)
        for j in principals:
            print("| " + i + " | " + j + " |")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 check-ability.py action_list_without_spaces_just_commas [exclude-list-file]\nEnsure that analysis/combined-gaad.json in the current directory.\nThe arns in the exclude list file path passed optionally are to exclude arns like administrative principals we know for a fact are safe.\nIf the action_list argument is privesc, it will cycle through known privesc vectors and provide a markdown table.')
        sys.exit(1)
    if len(sys.argv) > 2:
        f = open(sys.argv[2])
        excludelist = [x for x in f.read().split("\n") if not x==""]
        f.close()
    main(sys.argv[1], excludelist)

