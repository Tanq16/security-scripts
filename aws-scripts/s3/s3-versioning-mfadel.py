# S3 Bucket Versioning & MFA Delete
# ---------------------------------
# This script takes in the value of a profile that has an
# active session locally and prints out a markdown table
# with the account alias, bucket name, versioning, and MFA
# delete status for each bucket.

import boto3
import sys

def main(profile):
    session = boto3.Session(profile_name=profile)
    s3 = session.resource('s3')
    bucket_list = [bucket.name for bucket in s3.buckets.all()]

    print("| Account Alias | Bucket Name | Versioning | MFA Delete |")
    print("| --- | --- | --- | --- |")

    for bucket_name in bucket_list:
        response = s3.BucketVersioning(bucket_name)
        versioning = response.status
        mfadel = response.mfa_delete
        print(f"| {profile} | {bucket_name} | {versioning} | {mfadel} |")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 s3-versioning-mfadel.py <PROFILE>')
        sys.exit(1)
    profile = sys.argv[1]
    main(profile)
