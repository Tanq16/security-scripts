# EC2 Security Groups
# -------------------
# This script takes in the value of a profile and lists out
# all security groups in the account. It filters them based
# on Default Security Groups and unattached security groups.
# These can also be printed if necessary by uncommenting.
# The results is printed in markdown table format.

import boto3
import sys

def is_public_ip(eni):
    if 'Association' in eni and 'PublicIp' in eni['Association']:
        return True
    return False

def is_attached_public(enis,sg):
    data = {'GroupId': sg['GroupId'], 'GroupName': sg['GroupName']}
    x = "attached" if any(data in eni['Groups'] for eni in enis) else "not attached"
    public = "No"
    if x == "attached":
        attached_eni = [eni for eni in enis if data in eni['Groups']]
        if attached_eni:
            for eni in attached_eni:
                if is_public_ip(eni):
                    public = "Yes"
                    break
    return x, public

def print_security_group_details(security_groups, enis, region, profile):
    for sg in security_groups:
        sg_id = sg['GroupId']
        rules = sg['IpPermissions']
        if len(rules) == 1 and (rules[0]['IpProtocol'] == '-1' and len(rules[0]['IpRanges']) == 0 and len(rules[0]['Ipv6Ranges']) == 0 and len(rules[0]['PrefixListIds']) == 0):
            # SKIP Default SEGs
            # print(f"| {profile} | {sg_id} | NIL | Default Security Group - No external ingress |")
            # print("-----------------------------------------")
            continue
        attached_state, public = is_attached_public(enis, sg)
        if attached_state == "not attached":
            # pass
            continue
        print(f"| {profile} | {sg_id} | {public} |")
        for rule in sg['IpPermissions']:
            print(rule)
        print("-----------------------------------------")

def main(profile):
    session = boto3.Session(profile_name=profile)
    ec2_client = session.client('ec2', region_name='us-east-1')
    ec2_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    print("| Account Alias | SG ID | Public | Open Ports |")
    print("| --- | --- | --- | --- |")
    for region in ec2_regions:
        ec2_client = session.client('ec2', region_name=region)
        security_groups = []
        try:
            security_groups = ec2_client.describe_security_groups()['SecurityGroups']
            network_interfaces = ec2_client.describe_network_interfaces()['NetworkInterfaces']
        except:
            pass
        if security_groups == []:
            continue
        print_security_group_details(security_groups, network_interfaces, region, profile)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python3 ec2-security-groups.py <PROFILE>')
        sys.exit(1)
    profile = sys.argv[1]
    main(profile)
