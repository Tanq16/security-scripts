# AWS Resource Inventory
# ----------------------
# This script takes in the profile name and queries the cloud-
# control API to list the resources for a specific kind defined
# under the SELECTIVE_RESOURCE_LIST variable. It then prints the
# resource type, number of resources and the region for each
# resource type. The pseudo-complete resource type list can be
# generated via cloudformation (commented) but is not a 100%
# accurate list, though, for general inventorying and security
# analysis it should work fine.
# Note: the script is slow because of lack of multi-threading
# and the generally slow response generation by cloud-control.

import boto3
import sys

# Creation of AWS Resource Types List

# session = boto3.Session(profile_name=sys.argv[1])
# cloudformation_client = session.client("cloudformation", region_name='us-east-1')
# x = []
# y = None
# while True:
#     if not y:
#         cloudformation_response = cloudformation_client.list_types(Type="RESOURCE", Visibility="PUBLIC")
#     else:
#         cloudformation_response = cloudformation_client.list_types(Type="RESOURCE", Visibility="PUBLIC", NextToken=y)
#     for i in cloudformation_response["TypeSummaries"]:
#         if i.startswith("AWS"):
#             x.append(i["TypeName"])
#     try:
#         y = cloudformation_response["NextToken"]
#     except KeyError:
#         break
# for i in sorted(x):
#     print(i)

SELECTIVE_RESOURCE_LIST = ["AWS::AmazonMQ::Broker", "AWS::Backup::BackupPlan", "AWS::Batch::ComputeEnvironment", "AWS::Cassandra::Table", "AWS::CertificateManager::Account", "AWS::CertificateManager::Certificate", "AWS::Chatbot::MicrosoftTeamsChannelConfiguration", "AWS::Chatbot::SlackChannelConfiguration", "AWS::CloudFormation::Stack", "AWS::CloudFormation::StackSet", "AWS::CloudFront::Distribution", "AWS::CloudTrail::Trail", "AWS::CloudWatch::Alarm", "AWS::CodeArtifact::Repository", "AWS::CodeBuild::Project", "AWS::CodeCommit::Repository", "AWS::CodeDeploy::Application", "AWS::CodePipeline::Pipeline", "AWS::CodeStar::GitHubRepository","AWS::DirectoryService::MicrosoftAD", "AWS::DirectoryService::SimpleAD", "AWS::DynamoDB::GlobalTable", "AWS::DynamoDB::Table", "AWS::EC2::ClientVpnEndpoint", "AWS::EC2::CustomerGateway", "AWS::EC2::EIP", "AWS::EC2::Instance", "AWS::EC2::InternetGateway", "AWS::EC2::NatGateway", "AWS::EC2::TransitGateway", "AWS::EC2::VPC", "AWS::EC2::VPCEndpoint", "AWS::EC2::VPCPeeringConnection", "AWS::EC2::VPNConnection", "AWS::EC2::VPNGateway", "AWS::ECR::Repository", "AWS::ECS::Cluster", "AWS::ECS::Service", "AWS::EFS::FileSystem", "AWS::EKS::Cluster", "AWS::EKS::Nodegroup", "AWS::EMR::Cluster", "AWS::ElastiCache::CacheCluster", "AWS::ElasticBeanstalk::Application", "AWS::Elasticsearch::Domain", "AWS::FSx::FileSystem", "AWS::Glue::Database", "AWS::Glue::Registry", "AWS::GuardDuty::Detector", "AWS::IAM::OIDCProvider", "AWS::IAM::SAMLProvider", "AWS::IAM::ServiceLinkedRole", "AWS::IoT::Thing", "AWS::KMS::Key", "AWS::KafkaConnect::Connector", "AWS::Kinesis::Stream", "AWS::LakeFormation::Resource", "AWS::Lambda::Function", "AWS::MSK::Cluster", "AWS::MemoryDB::Cluster", "AWS::Neptune::DBCluster", "AWS::NetworkFirewall::Firewall", "AWS::OpsWorks::Instance", "AWS::Organizations::Account", "AWS::Organizations::Organization", "AWS::Organizations::OrganizationalUnit", "AWS::Organizations::Policy", "AWS::Organizations::ResourcePolicy", "AWS::RAM::ResourceShare", "AWS::RDS::DBCluster", "AWS::RDS::GlobalCluster", "AWS::Redshift::Cluster", "AWS::Route53::HostedZone", "AWS::S3::Bucket", "AWS::SES::ConfigurationSet", "AWS::SNS::Topic", "AWS::SQS::Queue", "AWS::SSM::Parameter", "AWS::SageMaker::App", "AWS::SageMaker::Domain", "AWS::SageMaker::Project", "AWS::SecretsManager::Secret"]

def get_resources(boto_session, region, resource_type):
    collected_resources = []
    list_operation_was_denied = False
    cloudcontrol_client = boto_session.client("cloudcontrol", region_name=region)

    y = None
    try:
        while True:
            if not y:
                cloudcontrol_response = cloudcontrol_client.list_resources(TypeName=resource_type)
            else:
                cloudcontrol_response = cloudcontrol_client.list_resources(TypeName=resource_type, NextToken=y)
            for resource in cloudcontrol_response["ResourceDescriptions"]:
                collected_resources.append(resource["Identifier"])
            try:
                y = cloudcontrol_response["NextToken"]
            except KeyError:
                break
    except Exception as _:
        pass
    return (resource_type, sorted(collected_resources))

def main(profile):
    session = boto3.Session(profile_name=profile)
    ec2_client = session.client('ec2', region_name='us-west-2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    for i in SELECTIVE_RESOURCE_LIST:
        for j in regions:
            resource_type, resources = get_resources(session, j, i)
            if len(resources) > 0:
                print(resource_type, str(len(resources)), "(" + j + ")")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 aws-resource-inventory.py <PROFILE>')
        sys.exit(1)
    profile = sys.argv[1]
    main(profile)
