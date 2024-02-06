# EC2 IMDSv1 in Use
# -----------------
# This script takes in the value of a profile that has an
# active session locally and prints out the number of EC2
# instances which have IMDSv1 enabled across all regions
# for that account. It also prints the instance IDs, region
# and account alias in a markdown table format.

import boto3
import sys

def list_ec2_instances(profile):
    session = boto3.Session(profile_name=profile)
    ec2_client = session.client('ec2', region_name='us-west-2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    num_instances = 0
    instances = []

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        list_instances = ec2_client.describe_instances()

        for res in list_instances['Reservations']:
            for i in res['Instances']:
                # check if IMDSv1 is enabled
                if i.get('MetadataOptions') and i['MetadataOptions'].get('HttpTokens') == 'optional':
                    num_instances += 1
                    instances.append({
                        'iid': i['InstanceId'],
                        'region': region,
                    })

    print('Number of instances with IMDSv1 enabled: ', num_instances)
    print("\n\n\n")
    print("| Account Alias | InstanceID | Region |\n| --- | --- | --- |")
    for i in instances:
        print(f"| {profile} | {i['iid']} | {i['region']} |")
    print("\n\n\n")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 ec2-imdsv1.py <PROFILE>')
        sys.exit(1)
    profile = sys.argv[1]
    list_ec2_instances(profile)
