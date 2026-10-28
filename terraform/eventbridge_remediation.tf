# EventBridge Rule & Lambda Self-Healing Remediation Mesh

data "archive_file" "lambda_remediation_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_drift_handler.zip"

  source {
    content  = file("${path.module}/../src/lambda_drift_handler.py")
    filename = "lambda_drift_handler.py"
  }
}

resource "aws_iam_role" "lambda_remediation_role" {
  name = "${local.name_prefix}-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "lambda_remediation_policy" {
  name = "${local.name_prefix}-remediation-policy"
  role = aws_iam_role.lambda_remediation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "OrganizationsQuarantineAccess"
        Effect = "Allow"
        Action = [
          "organizations:MoveAccount",
          "organizations:DescribeAccount",
          "organizations:ListRoots",
          "organizations:ListOrganizationalUnitsForParent"
        ]
        Resource = "*"
      },
      {
        Sid    = "SelfHealingRemediationActions"
        Effect = "Allow"
        Action = [
          "s3:PutAccountPublicAccessBlock",
          "s3:GetAccountPublicAccessBlock",
          "ec2:DetachInternetGateway",
          "ec2:DescribeInternetGateways",
          "cloudtrail:StartLogging",
          "cloudtrail:GetTrailStatus"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "drift_remediator" {
  filename         = data.archive_file.lambda_remediation_zip.output_path
  source_code_hash = data.archive_file.lambda_remediation_zip.output_base64sha256
  function_name    = "${local.name_prefix}-drift-remediator"
  role             = aws_iam_role.lambda_remediation_role.arn
  handler          = "lambda_drift_handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT        = var.environment
      QUARANTINE_OU_NAME = var.quarantine_ou_name
      DRY_RUN            = "false"
    }
  }

  tags = merge(local.common_tags, {
    Function = "AutomatedComplianceRemediator"
  })
}

resource "aws_cloudwatch_event_rule" "compliance_drift_rule" {
  name        = "${local.name_prefix}-compliance-drift-rule"
  description = "Captures AWS Config compliance state changes to NON_COMPLIANT and triggers auto-remediation"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "remediation_target" {
  rule      = aws_cloudwatch_event_rule.compliance_drift_rule.name
  target_id = "TriggerLambdaRemediation"
  arn       = aws_lambda_function.drift_remediator.arn
}

resource "aws_lambda_permission" "allow_eventbridge_to_call_lambda" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.compliance_drift_rule.arn
}
