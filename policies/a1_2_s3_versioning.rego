# METADATA
# title: A1.2 - S3 PHI buckets must have versioning enabled
# description: >
#   SOC 2 A1.2 requires system availability and recovery capabilities.
#   S3 buckets tagged DataClass=phi must have versioning enabled so
#   PHI overwrites are recoverable.
# custom:
#   framework: soc2
#   controls:
#     - "A1.2"
#   severity: high
#   gap: GAP-04
#   remediation: >
#     Add aws_s3_bucket_versioning with status = "Enabled".
package compliance.soc2.a1_2_s3_versioning

import rego.v1

deny contains msg if {
  bucket := input.configuration.root_module.resources[_]
  bucket.type == "aws_s3_bucket"
  bucket.expressions.tags.constant_value.DataClass == "phi"
  not has_versioning(bucket.name)
  msg := sprintf(
    "[A1.2][GAP-04] aws_s3_bucket.%s is tagged DataClass=phi but has no versioning enabled. PHI overwrites are unrecoverable. Add aws_s3_bucket_versioning with status=Enabled.",
    [bucket.name]
  )
}

has_versioning(bucket_name) if {
  ver := input.configuration.root_module.resources[_]
  ver.type == "aws_s3_bucket_versioning"
  ref := ver.expressions.bucket.references[_]
  ref == sprintf("aws_s3_bucket.%s.id", [bucket_name])
  ver.expressions.versioning_configuration[_].status.constant_value == "Enabled"
}