# IAM GAAD Combine
# ----------------
# This script navigates the directory path argument to
# collect and ingest all files ending with "*-gaad.json"
# and combine them into a final "combined-gaad.json". It
# is then stored within the "analysis" directory. The
# default file is meant for analysis and Neo4J ingestion
# while "combined-gaad-naive.json" is a simplistic join.
# Run `aws iam get-account-authorization-details` for all
# accounts and save the resulting JSON results as files
# with name like "<profile>-gaad.json". This can also be
# done by running the `iam-gaad-collector.sh` script. It
# will store all of the JSON files in a single folder after
# which, this script will run to build the combined JSON
# file. The resulting file is stored inside the analysis
# folder in the current directory.

import requests
import fnmatch
import json
import sys
import os

# get list of all possible actions
def gen_actions_dump():
    data = json.loads(str(requests.get('https://awspolicygen.s3.amazonaws.com/js/policies.js').content, encoding='utf-8').split('=')[1])
    actions = []
    for i in data['serviceMap']:
        prefix = data['serviceMap'][i]['StringPrefix']
        for j in data['serviceMap'][i]['Actions']:
            actions.append(prefix + ':' + j)
    return actions

actionsdump = gen_actions_dump()

# expand actions with wildcards to complete action list
def expand_actions(actionlist):
    retactions = []
    actions_temp = actionlist if type(actionlist)==list else [actionlist]
    for act in actions_temp:
        for outer_act in actionsdump:
            if fnmatch.fnmatch(outer_act, act):
                retactions.append(outer_act)
    return retactions

# get default policy version
def get_latest_policy(policy):
    pvl = [x for x in policy['PolicyVersionList'] if x['IsDefaultVersion']==True]
    policy['PolicyVersionList'] = pvl
    return policy

def combine_gaad_files(gaad_path):
    files = [file for file in os.listdir(gaad_path) if file.endswith('gaad.json')]
    combined = {'UserDetailList':[], 'GroupDetailList':[], 'RoleDetailList':[], 'Policies':[]}
    
    # naive combine
    added_arns = []
    for file in files:
        if file == 'combined-gaad.json':
            continue
        f = open(gaad_path + '/' + file)
        data = json.load(f)
        f.close()
        for i in data['UserDetailList']:
            if not i['Arn'] in added_arns:
                combined['UserDetailList'].append(i)
                added_arns.append(i['Arn'])
        for i in data['GroupDetailList']:
            if not i['Arn'] in added_arns:
                combined['GroupDetailList'].append(i)
                added_arns.append(i['Arn'])
        for i in data['RoleDetailList']:
            if not i['Arn'] in added_arns:
                combined['RoleDetailList'].append(i)
                added_arns.append(i['Arn'])
        for i in data['Policies']:
            if not i['Arn'] in added_arns:
                combined['Policies'].append(get_latest_policy(i))
                added_arns.append(i['Arn'])

    if not os.path.exists('./analysis'):
        os.makedirs('analysis')
    f = open('analysis/combined-gaad-naive.json', 'w')
    json.dump(combined, f)
    f.close()
    print("Naive GAAD Combine - Complete!\nBeginning Dynamic Combine\n")

    # processed combine
    combinedfinal = {'UserDetailList':[], 'GroupDetailList':[], 'RoleDetailList':[], 'Policies':[]}
    policiestemp = {'Policies':[]}
    for i in combined['UserDetailList']:
        temp = i
        # change group name to ARN to make it unique
        temp['GroupList'] = [":".join(i['Arn'].split(":")[:5]) + ":group/" + x for x in i['GroupList']]
        # append if no inline policies
        if not 'UserPolicyList' in i.keys():
            combinedfinal['UserDetailList'].append(temp)
            continue
        # build ARN for inline policies and append
        for j in range(len(i['UserPolicyList'])):
            temp['UserPolicyList'][j]['Arn'] = i['Arn'] + "/inline-policy/" + i['UserPolicyList'][j]['PolicyName']
            policiestemp['Policies'].append(temp['UserPolicyList'][j])
        combinedfinal['UserDetailList'].append(temp)
    print("Processed UserDetailList")
    for i in combined['GroupDetailList']:
        temp = i
        # append if no inline policies
        if not 'GroupPolicyList' in i.keys():
            combinedfinal['GroupDetailList'].append(temp)
            continue
        # build ARN for inline policies and append
        for j in range(len(i['GroupPolicyList'])):
            temp['GroupPolicyList'][j]['Arn'] = i['Arn'] + "/inline-policy/" + i['GroupPolicyList'][j]['PolicyName']
            policiestemp['Policies'].append(temp['GroupPolicyList'][j])
        combinedfinal['GroupDetailList'].append(temp)
    print("Processed GroupDetailList")
    for i in combined['RoleDetailList']:
        temp = i
        # append if no inline policies
        if not 'RolePolicyList' in i.keys():
            combinedfinal['RoleDetailList'].append(temp)
            continue
        # build ARN for inline policies and append
        for j in range(len(i['RolePolicyList'])):
            temp['RolePolicyList'][j]['Arn'] = i['Arn'] + "/inline-policy/" + i['RolePolicyList'][j]['PolicyName']
            policiestemp['Policies'].append(temp['RolePolicyList'][j])
        combinedfinal['RoleDetailList'].append(temp)
    print("Processed RoleDetailList")
    for i in combined['Policies']:
        temp = i
        # collapse version list to document
        if 'PolicyVersionList' in temp.keys():
            temp['PolicyDocument'] = i['PolicyVersionList'][0]['Document']
            _ = temp.pop('PolicyVersionList')
        policiestemp['Policies'].append(temp)
    print("Processed policy version lists")
    for i in policiestemp['Policies']:
        temp = i
        # edge case fix
        if type(i['PolicyDocument']['Statement']) == dict:
            temp['PolicyDocument']['Statement'] = [i['PolicyDocument']['Statement']]
        # add (not)action and (not)resource null values for each statement
        for stmt in temp['PolicyDocument']['Statement']:
            if 'Action' in stmt.keys():
                stmt['NotAction'] = None
                stmt['Action'] = expand_actions(stmt['Action'])
            else:
                stmt['Action'] = None
                stmt['NotAction'] = expand_actions(stmt['NotAction'])
            if 'Resource' in stmt.keys():
                stmt['NotResource'] = None
            else:
                stmt['Resource'] = None
            if not 'Condition' in stmt.keys():
                stmt['Condition'] = None
        combinedfinal['Policies'].append(temp)
    print("Processed policy statements")

    # write processed combined gaad
    f = open('analysis/combined-gaad.json', 'w')
    json.dump(combinedfinal, f)
    f.close()
    print("Dynamic GAAD Combine - Complete")

if __name__ == '__main__':
    if not os.path.exists('./gaads'):
        print('Usage: python3 iam-gaad-combine.py\nEnsure the `gaads` directory is present with the gaads of the accounts.')
        sys.exit(1)
    combine_gaad_files('gaads')
