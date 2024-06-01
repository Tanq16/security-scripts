# S3 Cleartext Transport
# ----------------------
# This script takes in the value of a profile that has an
# active session locally and prints out a markdown table
# of account aliases, bucket names, and whether cleartext
# transport is allowed. If not allowed, but the policy has
# a boolean condition key with aws:securetransport, then
# it prints the associated statement within the table.

from botocore.exceptions import ClientError
import boto3
import json
import sys
import os

def is_secure_transport(policy):
    retstatements = []
    for statement in policy['Statement']:
        if 'Condition' in statement and 'Bool' in statement['Condition'] and 'aws:SecureTransport' in statement['Condition']['Bool']:
            retstatements.append(json.dumps(statement))
    if len(retstatements) == 0:
        return "Allowed - No Condition"
    return ", ".join(retstatements)

def main(profile):
    session = boto3.Session(profile_name=profile)
    s3 = session.resource('s3')
    bucket_list = [bucket.name for bucket in s3.buckets.all()]

    print("| Account Alias | Bucket Name | Cleartext Transport |")
    print("| --- | --- | --- |")

    for bucket_name in bucket_list:
        bucket = s3.Bucket(bucket_name)
        try:
            policy = json.loads(bucket.Policy().policy)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                policy = None
            else:
                continue
        if policy == None:
            print(f"| {profile} | {bucket_name} | Allowed - No Bucket Policy |")
        else:
            print(f"| {profile} | {bucket_name} | " + is_secure_transport(policy) + " |")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 s3-list-bucket-policies.py <PROFILE>')
        sys.exit(1)
    profile = sys.argv[1]
    main(profile)
