# S3 Number of Objects per Bucket
# -------------------------------
# This script takes in the value of a profile that has an
# active session locally and prints out the name of all
# buckets within that account and a count of the number
# of objects along with the total size of each bucket.
# An ignore size above parameter can be added so that once
# the total bucket size during enumeration reaches it,
# the script will stop further enumeration. Default for
# that value is None. The results are printed to stdout.

import sys
import boto3
import concurrent.futures

def convert_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0 or unit == 'TB':
            break
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} {unit}"

def enumerator(bucket_name, sess, ignore_above_size):
    s3 = sess.resource('s3')
    ignored = False
    bucket = s3.Bucket(bucket_name)
    count, size = 0, 0
    for obj in bucket.objects.all():
        count += 1
        size += obj.size
        if (ignore_above_size != None) and (size > ignore_above_size):
            ignored = True
            break
    size = convert_size(size)
    if not ignored:
        print(f"{size} ({count})  :  {bucket_name}")
    else:
        print(f"{size} ({count})  :  {bucket_name}  :  IGNORED")

def main(profile, ignore_above_size=None):
    session = boto3.Session(profile_name=profile)
    s3 = session.resource('s3')
    bucket_names = [bucket.name for bucket in s3.buckets.all()]
    for bucket_name in bucket_names:
        enumerator(bucket_name, session, ignore_above_size)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 s3-size-num-objects.py <PROFILE> [ignore_above_size]')
        sys.exit(1)
    profile = sys.argv[1]
    if len(sys.argv) > 2:
        ignore_above_size = sys.argv[2]
    main(profile, ignore_above_size)
