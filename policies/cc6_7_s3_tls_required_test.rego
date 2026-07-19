package compliance.soc2.cc6_7_s3_tls

import rego.v1

compliant_input := {
  "configuration": {"root_module": {"resources": [
    {
      "type": "aws_s3_bucket",
      "name": "uploads",
      "expressions": {"tags": {"constant_value": {"DataClass": "phi"}}}
    },
    {
      "type": "aws_s3_bucket_policy",
      "name": "uploads_tls",
      "expressions": {
        "bucket": {"references": ["aws_s3_bucket.uploads.id"]}
      }
    }
  ]}}
}

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

test_missing_tls_policy_denied if {
  count(deny) == 1 with input as broken_input
}