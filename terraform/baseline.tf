######################################################################
# Acme Health — GRC Baseline (SOC 2 TSC)
#
# This file closes the gaps from GAPS.md using the starter's existing
# resources. We reference starter resources by their Terraform addresses.
# We do NOT modify main.tf — the starter stays intact and runnable.
######################################################################

######################################################################
# KMS — Customer-managed key for PHI encryption (CC6.1)
# Closes GAP-01 and GAP-02.
######################################################################

resource "aws_kms_key" "phi" {
  description             = "CMK for Acme Health PHI — S3 and DynamoDB"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name    = "${local.name_prefix}-phi-cmk"
    Purpose = "phi-encryption"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi"
  target_key_id = aws_kms_key.phi.key_id
}

######################################################################
# GAP-01: S3 SSE-KMS with customer CMK (CC6.1)
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-02: DynamoDB SSE with customer CMK (CC6.1)
######################################################################

resource "aws_dynamodb_table" "intake_encrypted" {
  name         = "${local.name_prefix}-submissions-enc-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }
}

######################################################################
# GAP-03: S3 bucket policy enforcing TLS (CC6.7)
######################################################################

resource "aws_s3_bucket_policy" "uploads_tls" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

######################################################################
# GAP-04: S3 versioning for PHI recovery (A1.2)
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# GAP-07: Least-privilege IAM policy replacing dynamodb:* and s3:*
# (CC6.3)
######################################################################

resource "aws_iam_role_policy" "lambda_least_privilege" {
  name = "intake-data-access-least-privilege"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBLeastPrivilege"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid    = "S3LeastPrivilege"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      },
      {
        Sid    = "KMSForPHI"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}

######################################################################
# GAP-08: API Gateway access logging (CC7.2)
######################################################################

resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/${local.name_prefix}"
  retention_in_days = 90
}

resource "aws_apigatewayv2_stage" "default_logged" {
  api_id      = aws_apigatewayv2_api.intake.id
  name        = "prod"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      responseLength = "$context.responseLength"
    })
  }

  default_route_settings {
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }
}

######################################################################
# Evidence vault — S3 with Object Lock GOVERNANCE mode
######################################################################

resource "aws_s3_bucket" "evidence" {
  bucket        = "${local.name_prefix}-evidence-${local.suffix}"
  force_destroy = false

  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.id
}

output "phi_kms_key_arn" {
  value = aws_kms_key.phi.arn
}