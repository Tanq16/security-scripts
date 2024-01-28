# IAM GAAD Analysis - Neo4J

```cypher
// get entities with pass-role and cfn-create-stack permissions with policy arn, condition, and resource
MATCH (y)-[:hasPolicy|inlinePolicy]->(p:policy)-[:defines]->(pp:permission)
where pp.effect = 'Allow' and 'iam:PassRole' in pp.action and 'cloudformation:CreateStack' in pp.action
RETURN y.arn, pp.condition, pp.resource, p.arn
```
```cypher
// get entities that can privesc with pass-role, create-lambda, and invoke-lambda
```
