# METADATA
# title: CC6.1 - S3 PHI buckets must use customer-managed KMS encryption
# description: >
#   SOC 2 CC6.1 requires logical access controls protecting information assets.
#   S3 buckets tagged DataClass=phi must use SSE-KMS with a customer CMK,
#   not AWS-managed SSE-S3. PHI keys must be under customer custody.
# custom:
#   framework: soc2
#   controls:
#     - "CC6.1"
#   severity: high
#   gap: GAP-01
#   remediation: >
#     Add aws_s3_bucket_server_side_encryption_configuration with
#     sse_algorithm = "aws:kms" and a customer-owned kms_master_key_id.
package compliance.soc2.cc6_1_s3_kms

import rego.v1

deny contains msg if {
  bucket := input.configuration.root_module.resources[_]
  bucket.type == "aws_s3_bucket"
  bucket.expressions.tags.constant_value.DataClass == "phi"
  not has_kms_encryption(bucket.name)
  msg := sprintf(
    "[CC6.1][GAP-01] aws_s3_bucket.%s is tagged DataClass=phi but has no KMS encryption configuration. Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=aws:kms.",
    [bucket.name]
  )
}

has_kms_encryption(bucket_name) if {
  enc := input.configuration.root_module.resources[_]
  enc.type == "aws_s3_bucket_server_side_encryption_configuration"
  ref := enc.expressions.bucket.references[_]
  ref == sprintf("aws_s3_bucket.%s.id", [bucket_name])
  rule := enc.expressions.rule[_]
  algo := rule.apply_server_side_encryption_by_default[_].sse_algorithm.constant_value
  algo == "aws:kms"
}