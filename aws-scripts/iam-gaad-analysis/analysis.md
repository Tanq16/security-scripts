# IAM GAAD Analysis (WIP)

First run the gaad collection script as follows &rarr;

```bash
bash iam-gaad-collector.sh
```

Then run the gaad-combine script &rarr;

```bash
python3 iam-gaad-combine.py
```

The `combined-gaad.json` file can be ingested into Neo4j using APOC and the following cypher queries &rarr;

```cypher
// load policies
CALL apoc.load.json("file://combined-gaad.json",'.Policies[*]') YIELD value as pol
MERGE(p:policy {name:pol.PolicyName, arn:pol.Arn});
```
```cypher
// load policies with (not)action on (not)resource, effect, and condition
CALL apoc.load.json("file://combined-gaad.json",'.Policies[*]') YIELD value as pol
UNWIND pol.PolicyDocument as pd
UNWIND pd.Statement as stmnt
MATCH (p:policy {arn:pol.Arn})
WHERE stmnt.Action IS NOT NULL AND stmnt.Resource IS NOT NULL
CREATE (perm:permission {action:stmnt.Action, notaction:stmnt.NotAction, resource:stmnt.Resource, notresource:stmnt.NotResource, effect:stmnt.Effect, condition:stmnt.Condition IS NOT NULL})
MERGE (p)-[:defines]->(perm)
```
```cypher
//load groups
CALL apoc.load.json("file://combined-gaad.json",'.GroupDetailList[*]') YIELD value as grp
MERGE(p:group {name:grp.GroupName, arn:grp.Arn});
```
```cypher
// load group attached policies
CALL apoc.load.json("file://combined-gaad.json",'.GroupDetailList[*]') YIELD value as grp
UNWIND grp.AttachedManagedPolicies as policy
MATCH (g:group {arn:grp.Arn})
MATCH (p:policy {arn:policy.PolicyArn})
CREATE (g)-[:hasPolicy]->(p)
```
```cypher
// load group inline policies
CALL apoc.load.json("file://combined-gaad.json",'.GroupDetailList[*]') YIELD value as grp
UNWIND grp.GroupPolicyList as policy
MATCH (g:group {arn:grp.Arn})
MATCH (p:policy {arn:policy.Arn})
CREATE (g)-[:inlinePolicy]->(p)
```
```cypher
// load users
CALL apoc.load.json("file://combined-gaad.json",'.UserDetailList[*]') YIELD value as usr
MERGE(p:user {name:usr.UserName, arn:usr.Arn});
```
```cypher
// load user-group membership
CALL apoc.load.json("file://combined-gaad.json",'.UserDetailList[*]') YIELD value as usr
UNWIND usr.GroupList as grouparn
MATCH (u:user {arn:usr.Arn})
MATCH (g:group {arn:grouparn})
CREATE (u)-[:memberOf]->(g);
```
```cypher
// load user attached policies
CALL apoc.load.json("file://combined-gaad.json",'.UserDetailList[*]') YIELD value as usr
UNWIND usr.AttachedManagedPolicies as policy
MATCH (u:user {arn:usr.Arn})
MATCH (p:policy {arn:policy.PolicyArn})
CREATE (u)-[:hasPolicy]->(p)
```
```cypher
// load user inline policies
CALL apoc.load.json("file://combined-gaad.json",'.UserDetailList[*]') YIELD value as usr
UNWIND usr.UserPolicyList as policy
MATCH (u:user {arn:usr.Arn})
MATCH (p:policy {arn:policy.Arn})
CREATE (g)-[:inlinePolicy]->(p)
```
```cypher
// load roles
CALL apoc.load.json("file://combined-gaad.json",'.RoleDetailList[*]') YIELD value as rle
MERGE(p:role {name:rle.RoleName, arn:rle.Arn});
```
```cypher
// load role attached policies
CALL apoc.load.json("file://combined-gaad.json",'.RoleDetailList[*]') YIELD value as rle
UNWIND rle.AttachedManagedPolicies as policy
MATCH (r:role {arn:rle.Arn})
MATCH (p:policy {arn:policy.PolicyArn})
CREATE (r)-[:hasPolicy]->(p)
```
```cypher
// load role inline policies
CALL apoc.load.json("file://combined-gaad.json",'.RoleDetailList[*]') YIELD value as rle
UNWIND rle.RolePolicyList as policy
MATCH (r:role {arn:rle.Arn})
MATCH (p:policy {arn:policy.Arn})
CREATE (r)-[:inlinePolicy]->(p)
```
```cypher
// load assumerole account root trust
CALL apoc.load.json("file://combined-gaad.json", "RoleDetailList[*]") YIELD value as rle
MATCH (r:role {arn: rle.Arn})
UNWIND rle.AssumeRolePolicyDocument as doc
UNWIND doc.Statement as stmnt
WITH stmnt,r
WHERE stmnt.Principal.AWS IS NOT NULL AND stmnt.Principal.AWS ENDS WITH ':root'
UNWIND stmnt.Principal.AWS as accroot
MERGE (a:account {number:split(accroot,":")[4]})
MERGE (a)-[:assumeRoleTrust]->(r);
```
```cypher
// load assumerole service trust
CALL apoc.load.json("file://combined-gaad.json", "RoleDetailList[*]") YIELD value as rle
MATCH (r:role {arn:rle.Arn})
UNWIND rle.AssumeRolePolicyDocument as doc
UNWIND doc.Statement as stmnt
with stmnt,r
WHERE stmnt.Principal.Service IS NOT NULL
UNWIND stmnt.Principal.Service as service
MERGE (s:service {name:service})
MERGE (s)-[:assumeRoleTrust]->(r)
```
```cypher
// load assumerole user trust
CALL apoc.load.json("file://combined-gaad.json", "RoleDetailList[*]") YIELD value as rle
MATCH (r:role {arn:rle.Arn})
UNWIND rle.AssumeRolePolicyDocument as doc
UNWIND doc.Statement as stmnt
WITH stmnt,r
WHERE stmnt.Principal.AWS IS NOT NULL AND stmnt.Principal.AWS CONTAINS ':user/'
UNWIND stmnt.Principal.AWS as user
MATCH (u:user {arn:user})
MERGE (u)-[:assumeRoleTrust]->(r)
```
```cypher
// load assumerole role trust
CALL apoc.load.json("file://combined-gaad.json", "RoleDetailList[*]") YIELD value as rle
MATCH (r:role {arn:rle.Arn})
UNWIND rle.AssumeRolePolicyDocument as doc
UNWIND doc.Statement as stmnt
WITH stmnt,r
WHERE stmnt.Principal.AWS IS NOT NULL AND stmnt.Principal.AWS CONTAINS ':role/'
UNWIND stmnt.Principal.AWS as role
MATCH (rr:role {arn:role})
MERGE (rr)-[:assumeRoleTrust]->(r)
```
```cypher
// load assumerole federated trust
CALL apoc.load.json("file://combined-gaad.json", "RoleDetailList[*]") YIELD value as rle
MATCH (r:role {arn:rle.Arn})
UNWIND rle.AssumeRolePolicyDocument as doc
UNWIND doc.Statement as stmnt
WITH stmnt,r
WHERE stmnt.Principal.Federated IS NOT NULL
UNWIND stmnt.Principal.Federated as fed
MERGE (rr:federated {arn:fed})
MERGE (rr)-[:federatedTrust]->(r)
```
```cypher
// load instance profiles
```
