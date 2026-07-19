package compliance.soc2.cc6_3_iam_least_privilege

import rego.v1

compliant_input := {
  "configuration": {"root_module": {"resources": [
    {
      "type": "aws_iam_role_policy",
      "name": "lambda_inline",
      "expressions": {
        "policy": {"constant_value": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"dynamodb:GetItem\"],\"Resource\":\"*\"}]}"}
      }
    }
  ]}}
}

broken_input := {
  "configuration": {"root_module": {"resources": [
    {
      "type": "aws_iam_role_policy",
      "name": "lambda_inline",
      "expressions": {
        "policy": {"constant_value": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"*\"}]}"}
      }
    }
  ]}}
}

test_compliant_passes if {
  count(deny) == 0 with input as compliant_input
}

test_wildcard_action_denied if {
  count(deny) == 1 with input as broken_input
}