######################################################################
# GitHub Actions OIDC role for the capstone gate (plan / apply / vault write).
# Reuses the account's existing GitHub OIDC provider from the labs.
# ARN is constructed (not data-sourced) so the CI role does not need
# iam:GetOpenIDConnectProvider — PowerUserAccess alone is enough to plan.
######################################################################

locals {
  github_oidc_provider_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
}

resource "aws_iam_role" "grc_gate" {
  name = "cgep-capstone-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = local.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:steggas/cgep-capstone:*",
            "repo:steggas@*/cgep-capstone@*:*",
          ]
        }
      }
    }]
  })
}

# Capstone CI applies Terraform and writes signed evidence. Narrow later if needed.
resource "aws_iam_role_policy_attachment" "grc_gate_poweruser" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_iam_role_policy" "grc_gate_iam_pass" {
  name = "capstone-passrole-and-oidc"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassLambdaRoles"
        Effect   = "Allow"
        Action   = ["iam:PassRole", "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies"]
        Resource = [
          aws_iam_role.lambda.arn,
          aws_iam_role.grc_gate.arn,
        ]
      },
      {
        Sid      = "ManageInlineLambdaPolicy"
        Effect   = "Allow"
        Action   = ["iam:PutRolePolicy", "iam:DeleteRolePolicy"]
        Resource = aws_iam_role.lambda.arn
      }
    ]
  })
}
