# METADATA
# title: CC6.1 - DynamoDB PHI tables must use customer-managed KMS encryption
# description: >
#   SOC 2 CC6.1 requires logical access controls protecting information assets.
#   DynamoDB tables tagged DataClass=phi must use SSE with a customer CMK.
# custom:
#   framework: soc2
#   controls:
#     - "CC6.1"
#   severity: high
#   gap: GAP-02
#   remediation: >
#     Add server_side_encryption block with enabled=true and a customer kms_key_arn.
package compliance.soc2.cc6_1_dynamodb_kms

import rego.v1

deny contains msg if {
  table := input.configuration.root_module.resources[_]
  table.type == "aws_dynamodb_table"
  table.expressions.tags.constant_value.DataClass == "phi"
  not has_kms_encryption(table.name)
  msg := sprintf(
    "[CC6.1][GAP-02] aws_dynamodb_table.%s is tagged DataClass=phi but has no customer KMS encryption. Add server_side_encryption block with a customer kms_key_arn.",
    [table.name]
  )
}

has_kms_encryption(table_name) if {
  table := input.configuration.root_module.resources[_]
  table.type == "aws_dynamodb_table"
  table.name == table_name
  sse := table.expressions.server_side_encryption[_]
  sse.enabled.constant_value == true
  sse.kms_key_arn != null
}