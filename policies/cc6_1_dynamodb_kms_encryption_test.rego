package compliance.soc2.cc6_1_dynamodb_kms

import rego.v1

compliant_input := {
  "configuration": {"root_module": {"resources": [
    {
      "type": "aws_dynamodb_table",
      "name": "intake",
      "expressions": {
        "tags": {"constant_value": {"DataClass": "phi"}},
        "server_side_encryption": [{"enabled": {"constant_value": true}, "kms_key_arn": {"references": ["aws_kms_key.phi.arn"]}}]
      }
    }
  ]}}
}

broken_input := {
  "configuration": {"root_module": {"resources": [
    {
      "type": "aws_dynamodb_table",
      "name": "intake",
      "expressions": {
        "tags": {"constant_value": {"DataClass": "phi"}}
      }
    }
  ]}}
}

test_compliant_passes if {
  count(deny) == 0 with input as compliant_input
}

test_missing_kms_denied if {
  count(deny) == 1 with input as broken_input
}