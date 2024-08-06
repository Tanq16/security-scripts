# GCP - Analyze IAM
# -----------------
# This script is directly inspired by Rhinosec's GCP privilege escalation tool
# (https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/tree/master).
# This uses collected IAM data to search for principals that can perform privilege
# escalation actions and categorizes them into 3 groups: overly-permissive IAM
# principals that have Owner/Editor/Viewer access, permissive principals that have
# *Admin roles for services, and privesc principals that can escalate to higher
# privileges.

import json
import sys
import os

PRIVESC_METHODS = {
    'UpdateIAMRole': [
            'iam.roles.update'
        ],
    'CreateServiceAccountKey': [
            'iam.serviceAccountKeys.create'
        ],
    'GetServiceAccountAccessToken': [
            'iam.serviceAccounts.getAccessToken'
        ],
    'ServiceAccountImplicitDelegation': [
            'iam.serviceAccounts.implicitDelegation'
        ],
    'ServiceAccountSignBlob': [
            'iam.serviceAccounts.signBlob'
        ],
    'ServiceAccountSignJwt': [
            'iam.serviceAccounts.signJwt'
        ],
    'SetOrgPolicyConstraints': [
            'orgpolicy.policy.set'
        ],
    'CreateServiceAccountHMACKey': [
            'storage.hmacKeys.create'
        ],
    'CreateDeploymentManagerDeployment': [
            'deploymentmanager.deployments.create'
        ],
    'RCECloudBuildBuildServer': [
            'cloudbuild.builds.create'
        ],
    'ExfilCloudFunctionCredsAuthCall': [
            'cloudfunctions.functions.create',
            'cloudfunctions.functions.sourceCodeSet',
            'iam.serviceAccounts.actAs',
            'cloudfunctions.functions.call'
        ],
    'ExfilCloudFunctionCredsUnauthCall': [
            'cloudfunctions.functions.create',
            'cloudfunctions.functions.sourceCodeSet',
            'iam.serviceAccounts.actAs',
            'cloudfunctions.functions.setIamPolicy'
        ],
    'UpdateCloudFunction': [
            'cloudfunctions.functions.sourceCodeSet',
            'cloudfunctions.functions.update',
            'iam.serviceAccounts.actAs'
        ],
    'CreateGCEInstanceWithSA': [
            'compute.disks.create',
            'compute.instances.create',
            'compute.instances.setMetadata',
            'compute.instances.setServiceAccount',
            'compute.subnetworks.use',
            'compute.subnetworks.useExternalIp',
            'iam.serviceAccounts.actAs'
        ],
    'ExfilCloudRunServiceUnauthCall': [
            'run.services.create',
            'iam.serviceaccounts.actAs',
            'run.services.setIamPolicy'
        ],
    'ExfilCloudRunServiceAuthCall': [
            'run.services.create',
            'iam.serviceaccounts.actAs',
            'run.routes.invoke'
        ],
    'CreateAPIKey': [
            'serviceusage.apiKeys.create'
        ],
    'ViewExistingAPIKeys': [
            'serviceusage.apiKeys.list'
        ],
    'SetOrgIAMPolicy': [
            'resourcemanager.organizations.setIamPolicy'
        ],
    'SetFolderIAMPolicy': [
            'resourcemanager.folders.setIamPolicy'
        ],
    'SetProjectIAMPolicy': [
            'resourcemanager.projects.setIamPolicy'
        ],
    'SetServiceAccountIAMPolicy': [
            'iam.serviceAccounts.setIamPolicy'
        ],
    'CreateCloudSchedulerHTTPRequest': [
            'cloudscheduler.jobs.create',
            'cloudscheduler.locations.list',
            'iam.serviceAccounts.actAs'
        ]
}

def preprocess_policies(policies_init):
    overly_permissive = []
    permissive = []
    policies_shrunk = []
    for i in policies_init:
        scope_id, scope_type = i["id"], i["type"]
        bindings = []
        for j in i["policy"]["bindings"]:
            if j["role"] == "roles/editor" or j["role"] == "roles/owner" or j["role"] == "roles/viewer":
                overly_permissive.append({"id": scope_id, "type": scope_type, "binding":j})
                continue
            if j["role"].endswith("admin"):
                permissive.append({"id": scope_id, "type": scope_type, "binding":j})
            bindings.append(j.copy())
        policies_shrunk.append({"id":scope_id, "type":scope_type, "policy": {"bindings":bindings}})
    return overly_permissive, permissive, policies_shrunk

def destill_permissions(roles, policies_shrunk):
    policies = policies_shrunk
    for i in policies:
        for j in i["policy"]["bindings"]:
            permissions = [x["includedPermissions"] for x in roles if x["name"]==j["role"]][0]
            j["role"] = permissions
    return policies

def find_privescs(policies, policies_init, projects, folders, org):
    privescs = []
    for i in policies:
        for k in i["policy"]["bindings"]:
            for j in PRIVESC_METHODS.keys():
                possible = all(perms in k["role"] for perms in PRIVESC_METHODS[j])
                if possible:
                    privescs.append({"id":i["id"], "type":i["type"], "principal":k["members"], "method":j})
    return privescs

def print_results(overly_permissive, permissive, privescs):
    print("The following is a list of privesc methods, the principals that can perform the method, and the scope they have permissions to perform it on:\n")
    print("| Method | Principal | Scope Type | Scope ID |")
    print("| --- | --- | --- | --- |")
    for i in privescs:
        for j in i["principal"]:
            print("| " + i["method"] + " | " + j + " | " + i["type"] + " | " + i["id"] + " | ")

    print("\n\nThe following is a list of overly-permissive principals identified during automated triage:\n")
    print("| Principal | Scope | Role |")
    print("| --- | --- | --- |")
    for i in overly_permissive:
        for j in i["binding"]["members"]:
            print("| " + j + " | " + i["type"]+"/"+i["id"] + " | " + i["binding"]["role"] + " |")

    print("\n\nThe following is a list of permissive principals (*admin) identified during automated triage:\n")
    print("| Principal | Scope | Role |")
    print("| --- | --- | --- |")
    for i in permissive:
        for j in i["binding"]["members"]:
            print("| " + j + " | " + i["type"]+"/"+i["id"] + " | " + i["binding"]["role"] + " |")

def main():
    f = open("output/organization-info.json")
    org = json.loads(f.read())
    f.close()
    f = open("output/projects.json")
    projects = json.loads(f.read())
    f.close()
    f = open("output/folders.json")
    folders = json.loads(f.read())
    f.close()
    f = open("output/roles.json")
    roles = json.loads(f.read())
    f.close()
    f = open("output/projects-policies.json")
    policies_init = json.loads(f.read())
    f.close()

    overly_permissive, permissive, policies_shrunk = preprocess_policies(policies_init)
    policies = destill_permissions(roles, policies_shrunk)
    privescs = find_privescs(policies, policies_init, projects, folders, org)

    f = open("output/results-privescs.json", "w")
    f.write(json.dumps(privescs))
    f.close()
    f = open("output/results-overly-permissive.json", "w")
    f.write(json.dumps(overly_permissive))
    f.close()
    f = open("output/results-permissive.json", "w")
    f.write(json.dumps(permissive))
    f.close()

    print_results(overly_permissive, permissive, privescs)

if __name__ == "__main__":
    main()
