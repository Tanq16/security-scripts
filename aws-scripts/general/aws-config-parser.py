# AWS Config Parser
# -----------------
# Run as python3 aws-config-parser.py | jq '<your-commands>'
# using jq, print values for access keys; example:
# for devacc's secret access key: `jq '.devacc.sak'`.

import os
import sys
import json
import boto3
from configparser import ConfigParser

def get_aws_profiles():
    config = ConfigParser()
    config.read(os.path.expanduser('~/.aws/credentials'))

    profiles = {}
    # parse for access key IDs and secret access keys
    for section in config.sections():
        profile = {
            'aki': config[section]['aws_access_key_id'],
            'sak': config[section]['aws_secret_access_key'],
        }
        # parse for session token if present (STS sessions)
        if 'aws_session_token' in config[section]:
            profile['st'] = config[section]['aws_session_token']
        profiles[section] = profile

    return profiles

def main():
    profiles = get_aws_profiles()
    print(json.dumps(profiles))

if __name__ == '__main__':
    main()
