# AWS GAAD Collector
# ------------------
# This scripts reads the profile_names file to get
# all profiles and then make a directory called gaads
# with the gaads of each account with the names intact.

import os
import sys
import json
import boto3

def main():
    f = open("profile_names")
    profile_names = f.readlines()
    f.close()
    if not os.path.exists('./gaads'):
        os.makedirs('gaads')
    for i in profiles_names:
        session = boto3.Session(profile_name=i)
        iam = session.client('iam')
        account_authorization_details = iam.get_account_authorization_details()
        with open('gaads/' + i + '-gaad.json', 'w') as f:
            f.write(json.dumps(account_authorization_details))

if __name__ == '__main__':
    main()
