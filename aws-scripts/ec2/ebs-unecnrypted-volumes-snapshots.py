# EBS Unencrypted Volumes & Snapshots
# -----------------------------------
# This script takes in the value of a profile that has an
# active session locally and prints out the number of
# unecnrypted volumes and snapshots across all regions for
# that account. It also prints the number of unencrypted
# volumes that are attached and in use. The actual data is
# printed in a markdown table format.

import boto3
import sys

def list_ebs_volumes(profile):
    session = boto3.Session(profile_name=profile)
    ec2_client = session.client('ec2', region_name='us-west-2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    unencrypted_volumes = 0
    unencrypted_snapshots = 0
    unencrypted_attached_volumes = 0

    uvols = []
    usnaps = []
    uattvols = []

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        volumes,snapshots = [],[]

        try:
            volumes = ec2_client.describe_volumes(MaxResults=9999)['Volumes']
            snapshots = ec2_client.describe_snapshots(OwnerIds=['self'], MaxResults=9999)['Snapshots']
        except:
            pass

        # Check each volume and snapshot for encryption and attachment
        for volume in volumes:
            if 'Encrypted' in volume and not volume['Encrypted']:
                unencrypted_volumes += 1
                uvols += volume['VolumeId']
                if len(volume['Attachments']) > 0 and volume['State'] == 'in-use':
                    unencrypted_attached_volumes += 1
                    uattvols += ["| " + " | ".join([profile, volume['VolumeId'], region]) + " |"]
        for snapshot in snapshots:
            if 'Encrypted' in snapshot and not snapshot['Encrypted']:
                unencrypted_snapshots += 1
                usnaps += ["| " + " | ".join([profile, snapshot['SnapshotId'], region]) + " |"]

    print('Unencrypted Volumes: ', unencrypted_volumes)
    print('Unencrypted Snapshots: ', unencrypted_snapshots)
    print('Unencrypted Volumes (attached & in-use): ', unencrypted_attached_volumes)

    print("\n\n\n")

    print("| Account Alias | VolumeId | Region |\n| --- | --- | --- |")
    for i in uattvols:
        print(i)

    print("\n\n\n")

    print("| Account Alias | SnapshotId | Region |\n| --- | --- | --- |")
    for i in usnaps:
        print(i)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 ebs-unencrypted-volumes-snapshots.py <PROFILE>')
        sys.exit(1)
    profile = sys.argv[1]
    list_ebs_volumes(profile)
