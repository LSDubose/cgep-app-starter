# METADATA
# title: CC6.7 - S3 PHI buckets must deny non-TLS requests
# description: >
#   SOC 2 CC6.7 requires protection of data in transit.
#   S3 buckets tagged DataClass=phi must have a bucket policy
#   denying requests where aws:SecureTransport is false.
# custom:
#   framework: soc2
#   controls:
#     - "CC6.7"
#   severity: high
#   gap: GAP-03
#   remediation: >
#     Add aws_s3_bucket_policy with a Deny statement on
#     aws:SecureTransport = false.
package compliance.soc2.cc6_7_s3_tls

import rego.v1

deny contains msg if {
  bucket := input.configuration.root_module.resources[_]
  bucket.type == "aws_s3_bucket"
  bucket.expressions.tags.constant_value.DataClass == "phi"
  not has_tls_policy(bucket.name)
  msg := sprintf(
    "[CC6.7][GAP-03] aws_s3_bucket.%s is tagged DataClass=phi but has no bucket policy denying non-TLS requests. Add a Deny on aws:SecureTransport=false.",
    [bucket.name]
  )
}

has_tls_policy(bucket_name) if {
  policy := input.configuration.root_module.resources[_]
  policy.type == "aws_s3_bucket_policy"
  ref := policy.expressions.bucket.references[_]
  ref == sprintf("aws_s3_bucket.%s.id", [bucket_name])
}