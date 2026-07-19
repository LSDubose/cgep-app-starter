package compliance.soc2.cc6_1_s3_kms

import rego.v1

# Compliant: PHI bucket with KMS encryption
compliant_input := {
  "configuration": {"root_module": {"resources": [
    {
      "type": "aws_s3_bucket",
      "name": "uploads",
      "expressions": {"tags": {"constant_value": {"DataClass": "phi"}}}
    },
    {
      "type": "aws_s3_bucket_server_side_encryption_configuration",
      "name": "uploads",
      "expressions": {
        "bucket": {"references": ["aws_s3_bucket.uploads.id"]},
        "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "aws:kms"}}]}]
      }
    }
  ]}}
}

# Non-compliant: PHI bucket with no KMS encryption
broken_input := {
  "configuration": {"root_module": {"resources": [
    {
      "type": "aws_s3_bucket",
      "name": "uploads",
      "expressions": {"tags": {"constant_value": {"DataClass": "phi"}}}
    }
  ]}}
}

test_compliant_passes if {
  count(deny) == 0 with input as compliant_input
}

test_missing_kms_denied if {
  count(deny) == 1 with input as broken_input
}