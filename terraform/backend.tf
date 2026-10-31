# Remote state so CI can plan/apply the same workspace.
# Bucket bootstrapped once outside Terraform (acme-capstone-tfstate-steggas).
terraform {
  backend "s3" {
    bucket = "acme-capstone-tfstate-steggas"
    key    = "capstone/terraform.tfstate"
    region = "us-east-1"
  }
}
