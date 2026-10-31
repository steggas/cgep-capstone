output "api_url" {
  value       = "${aws_apigatewayv2_api.intake.api_endpoint}/intake"
  description = "POST /intake endpoint."
}

output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket where intake attachments land."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "phi_kms_key_arn" {
  value       = aws_kms_key.phi.arn
  description = "Customer CMK wrapping PHI stores and the evidence vault."
}

output "evidence_bucket" {
  value       = aws_s3_bucket.evidence.id
  description = "Object Lock evidence vault bucket."
}

output "grc_gate_role_arn" {
  value       = aws_iam_role.grc_gate.arn
  description = "GitHub Actions OIDC role for the GRC gate."
}

output "cloudtrail_name" {
  value = aws_cloudtrail.mgmt.name
}
