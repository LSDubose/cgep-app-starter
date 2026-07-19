# METADATA
# title: CC6.3 - Lambda IAM policies must not use wildcard actions
# description: >
#   SOC 2 CC6.3 requires authorization based on least privilege.
#   Lambda IAM role policies must not use dynamodb:* or s3:*
#   on workload resources. Wildcard actions violate least privilege.
# custom:
#   framework: soc2
#   controls:
#     - "CC6.3"
#   severity: high
#   gap: GAP-07
#   remediation: >
#     Replace dynamodb:* and s3:* with specific actions like
#     dynamodb:PutItem, dynamodb:GetItem, s3:PutObject, s3:GetObject.
package compliance.soc2.cc6_3_iam_least_privilege

import rego.v1

wildcard_actions := {"dynamodb:*", "s3:*", "kms:*", "*"}

deny contains msg if {
  policy := input.configuration.root_module.resources[_]
  policy.type == "aws_iam_role_policy"
  decoded := json.unmarshal(policy.expressions.policy.constant_value)
  statement := decoded.Statement[_]
  statement.Effect == "Allow"
  action := statement.Action
  action == wildcard_actions[_]
  msg := sprintf(
    "[CC6.3][GAP-07] aws_iam_role_policy.%s contains wildcard action '%s'. Replace with specific actions to enforce least privilege.",
    [policy.name, action]
  )
}