# METADATA
# title: HIPAA 164.312(a)(2)(iv) — S3 uploads use customer CMK
# description: "Every aws_s3_bucket must have SSE-KMS via aws_s3_bucket_server_side_encryption_configuration (GAP-01)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms and a customer CMK."
#   gap: GAP-01
package compliance.hipaa.s3_cmk

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_kms_encryption(bucket)
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv) / GAP-01] %s: missing SSE-KMS configuration. Remediation: add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=aws:kms and a customer CMK.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_kms_encryption(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	uses_kms(r)
}

uses_kms(r) if {
	some rule in r.expressions.rule
	some apply in rule.apply_server_side_encryption_by_default
	apply.sse_algorithm.constant_value == "aws:kms"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
