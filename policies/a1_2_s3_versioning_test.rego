package compliance.soc2.a1_2_s3_versioning

import rego.v1

compliant_input := {
  "configuration": {"root_module": {"resources": [
    {
      "type": "aws_s3_bucket",
      "name": "uploads",
      "expressions": {"tags": {"constant_value": {"DataClass": "phi"}}}
    },
    {
      "type": "aws_s3_bucket_versioning",
      "name": "uploads",
      "expressions": {
        "bucket": {"references": ["aws_s3_bucket.uploads.id"]},
        "versioning_configuration": [{"status": {"constant_value": "Enabled"}}]
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

test_missing_versioning_denied if {
  count(deny) == 1 with input as broken_input
}