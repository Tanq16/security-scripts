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
CALL apoc.load.json("file://combined-gaad.json",'.Policies[*]') YIELD value as row
MERGE(p:policy {name:row.PolicyName, arn:row.Arn});
```
```cypher
// load policies (not)action on (not)resource
CALL apoc.load.json("file://combined-gaad.json",'.Policies[*]') YIELD value as row
UNWIND row.PolicyDocument as pd
UNWIND pd.Statement as stmt
MATCH (p:policy {arn:row.Arn})
WHERE stmt.Action IS NOT NULL AND stmt.Resource IS NOT NULL
MERGE (pp:permission {action:stmt.Action, resource:stmt.Resource, effect:stmt.Effect, condition:COALESCE(stmt.Condition,false)})
MERGE (p)-[:defines]->(pp)
```
```cypher
//load groups
CALL apoc.load.json("file://combined-gaad.json",'.GroupDetailList[*]') YIELD value as row
MERGE(p:group {name:row.GroupName, arn:row.Arn});
```
```cypher
// load group attached policies
CALL apoc.load.json("file://combined-gaad.json",'.GroupDetailList[*]') YIELD value as row
UNWIND row.AttachedManagedPolicies as policy
MATCH (g:group {arn:row.Arn})
MATCH (p:policy {arn:policy.PolicyArn})
CREATE (g)-[:hasPolicy]->(p)
```
```cypher
// load group inline policies
CALL apoc.load.json("file://combined-gaad.json",'.GroupDetailList[*]') YIELD value as row
UNWIND row.GroupPolicyList as policy
MATCH (g:group {arn:row.Arn})
MATCH (p:policy {arn:policy.Arn})
CREATE (g)-[:inlinePolicy]->(p)
```
```cypher
// load users
CALL apoc.load.json("file://combined-gaad.json",'.UserDetailList[*]') YIELD value as row
MERGE(p:user {name:row.UserName, arn:row.Arn});
```
```cypher
// load user-group membership
CALL apoc.load.json("file://combined-gaad.json",'.UserDetailList[*]') YIELD value as row
UNWIND row.GroupList as grouparn
MATCH (u:user {arn:row.Arn})
MATCH (g:group {arn:grouparn})
CREATE (u)-[:memberOf]->(g);
```
```cypher
// load user attached policies
CALL apoc.load.json("file://combined-gaad.json",'.UserDetailList[*]') YIELD value as row
UNWIND row.AttachedManagedPolicies as policy
MATCH (u:user {arn:row.Arn})
MATCH (p:policy {arn:policy.PolicyArn})
CREATE (u)-[:hasPolicy]->(p)
```
```cypher
// load user inline policies
CALL apoc.load.json("file://combined-gaad.json",'.UserDetailList[*]') YIELD value as row
UNWIND row.UserPolicyList as policy
MATCH (u:user {arn:row.Arn})
MATCH (p:policy {arn:policy.Arn})
CREATE (g)-[:inlinePolicy]->(p)
```
```cypher
// load roles
CALL apoc.load.json("file://combined-gaad.json",'.RoleDetailList[*]') YIELD value as row
MERGE(p:role {name:row.RoleName, arn:row.Arn});
```
```cypher
// load role attached policies
CALL apoc.load.json("file://combined-gaad.json",'.RoleDetailList[*]') YIELD value as row
UNWIND row.AttachedManagedPolicies as policy
MATCH (r:role {arn:row.Arn})
MATCH (p:policy {arn:policy.PolicyArn})
CREATE (r)-[:hasPolicy]->(p)
```
```cypher
// load role inline policies
CALL apoc.load.json("file://combined-gaad.json",'.RoleDetailList[*]') YIELD value as row
UNWIND row.RolePolicyList as policy
MATCH (r:role {arn:row.Arn})
MATCH (p:policy {arn:policy.Arn})
CREATE (r)-[:inlinePolicy]->(p)
```
```cypher
// load assume role trust policies
```
```cypher
// load instance profiles
```
