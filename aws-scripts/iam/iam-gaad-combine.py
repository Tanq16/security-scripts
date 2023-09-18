# IAM GAAD Combine
# ----------------
# This script navigates the directory path argument to
# collect and ingest all files ending with "*-gaad.json"
# and combine them into a final "combined-gaad.json". It
# is then stored within the "analysis" directory.
# 
# Run `aws iam get-account-authorization-details` for all
# accounts and save the resulting JSON results as files
# with name like "<profile>-gaad.json". Store all of the
# JSON files in a single folder and run this script from
# that folder to build the combined JSON file. The result
# file is stored inside the analysis folder in the cwd.

import json
import sys
import os

def get_latest_policy(policy):
    pvl = [x for x in policy['PolicyVersionList'] if x['IsDefaultVersion']==True]
    policy['PolicyVersionList'] = pvl
    return policy

def combine_gaad_files(gaad_path):
    files = [file for file in os.listdir(gaad_path) if file.endswith('gaad.json')]
    combined = {'UserDetailList':[], 'GroupDetailList':[], 'RoleDetailList':[], 'Policies':[]}

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
    f = open('analysis/combined-gaad.json', 'w')
    json.dump(combined, f)
    f.close()

if __name__ == '__main__':
    if not os.path.exists('./gaads'):
        print('Usage: python3 iam-gaad-combine.py\nEnsure the `gaads` directory is present with the gaads of the accounts.')
        sys.exit(1)
    combine_gaad_files('gaads')
