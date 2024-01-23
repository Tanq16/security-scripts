# IAM Create Console Session from CLI
# -----------------------------------
# Run as python3 iam-gen-console-from-cli.py
# The script retrieves and prints all profile names
# available. User can then select a profile and the
# script will use the session credentials to generate
# a signed URL to convert into a console session.

import os
import sys
import json
import urllib
import requests
from configparser import ConfigParser

def get_aws_profiles():
    config = ConfigParser()
    config.read(os.path.expanduser('~/.aws/credentials'))
    profiles = {}
    for section in config.sections():
        profile = {
            'access_key_id': config[section]['aws_access_key_id'],
            'secret_access_key': config[section]['aws_secret_access_key'],
        }
        if 'aws_session_token' in config[section]:
            profile['session_token'] = config[section]['aws_session_token']
        profiles[section] = profile
    return profiles

def main():
    profiles = get_aws_profiles()
    print("Profiles:")
    for i in profiles.keys():
        print("- " + i)
    print()
    selected = input("Enter profile name to convert to console credentials: ")
    credentials = profiles[selected]

    url = "https://signin.aws.amazon.com/federation?Action=getSigninToken&SessionDuration=43200&Session="
    url += urllib.parse.quote_plus(json.dumps(credentials))
    r = requests.get(url)
    signin_token = json.loads(r.text)["SigninToken"]
    url = "https://signin.aws.amazon.com/federation?Action=login&Issuer=etherios.king&Destination="
    url += urllib.parse.quote_plus("https://console.aws.amazon.com/") + "&SigninToken=" + signin_token
    print("\nURL is as follows:\n")
    print(url)

if __name__ == '__main__':
    main()
