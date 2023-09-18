# IAM MFA, Keys & Password Age
# ----------------------------
# This script takes in the value of a profile that has an
# active session locally and prints out a json object with
# a key "data" that has a list of users, each of which is
# a dictionary with keys "user" (the username) and "keys"
# (a list of all >90 day old active keys for that user)
# along with the age of the keys (>90 days) in no. of days.
# It also prints the console password age for each user.
# It also prints out whether the user has MFA enrolled or
# not. All of this information is printed out in MD-table
# format.

import sys
import csv
import json
import time
import boto3
from dateutil.parser import parse
from datetime import datetime, timedelta

def get_active_keys(iam_client, user_name):
    active_keys = []
    response = iam_client.list_access_keys(UserName=user_name)
    for access_key in response['AccessKeyMetadata']:
        if access_key['Status'] == 'Active':
            last_rotated = access_key['CreateDate'].replace(tzinfo=None)
            if datetime.utcnow() - last_rotated > timedelta(days=90):
                active_keys.append(str((datetime.utcnow() - last_rotated).days))
    return active_keys

def get_password_age(user_name, credsreport):
    data = [credsreport[x] for x in credsreport.keys() if credsreport[x]['user'] == user_name][0]
    x = data['password_last_changed']
    if x == 'not_supported' or x == 'N/A':
        return x
    return str((datetime.utcnow() - parse(x).replace(tzinfo=None)).days)

def get_key_last_usage(user_name, credsreport):
    data = [credsreport[x] for x in credsreport.keys() if credsreport[x]['user'] == user_name][0]
    x, y = data['access_key_1_last_used_date'], data['access_key_2_last_used_date']
    z = []
    if not x == 'N/A':
        z.append(str((datetime.utcnow() - parse(x).replace(tzinfo=None)).days))
    else:
        z.append(x)
    if not y == 'N/A':
        z.append(str((datetime.utcnow() - parse(y).replace(tzinfo=None)).days))
    else:
        z.append(y)
    return ', '.join(z)

def generate_credential_report_graceful(iam_client):
    for _ in range(3):
        try:
            resp = iam_client.generate_credential_report()
            if resp['State'] == 'COMPLETE':
                return True
        except Exception as e:
            pass
        time.sleep(3)
    return False

def main(profile_name):
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client('iam')

    resp = generate_credential_report_graceful(iam_client)
    if not resp:
        print('ERROR: Couldn\'t generate credential report')
        sys.exit(1)
    response = iam_client.get_credential_report()
    content = response["Content"].decode("utf-8").split("\n")
    creds_reader = csv.DictReader(content, delimiter=",")
    credsreport = dict(enumerate(list(creds_reader)))

    users = []
    response = iam_client.list_users(MaxItems=999)
    print("| Account Alias | Username | MFA Status | Password Age | Keys (and Age) | AK Last Used Metadata |")
    print("| --- | --- | --- | --- | --- | --- |")
    for user in response['Users']:
        user_name = user['UserName']
        active_keys = get_active_keys(iam_client, user_name)
        mfadevs = iam_client.list_mfa_devices(UserName=user_name)
        mfastatus = "Yes" if len(mfadevs['MFADevices']) > 0 else "No"
        pw_age = get_password_age(user_name, credsreport)
        ak_usage = get_key_last_usage(user_name, credsreport)
        if len(active_keys) == 0:
            print(f"| {profile} | {user_name} | {mfastatus} | {pw_age} | No Old Keys | AKLU: " + ak_usage + " |")
        else:
            print(f"| {profile} | {user_name} | {mfastatus} | {pw_age} | " + ", ".join(active_keys) + " | AKLU: " + ak_usage + " |")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 iam-keyage-mfa-pwage.py <PROFILE>')
        sys.exit(1)
    profile = sys.argv[1]
    main(profile)
