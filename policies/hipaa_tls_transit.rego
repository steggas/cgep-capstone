# METADATA
# title: HIPAA 164.312(e)(1) — S3 denies non-TLS
# description: "Uploads (and other app) buckets must deny aws:SecureTransport=false (GAP-03)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: high
#   remediation: "Attach an aws_s3_bucket_policy that Deny s3:* when aws:SecureTransport is false."
#   gap: GAP-03
package compliance.hipaa.tls_transit

import rego.v1

deny contains msg if {
	bucket := app_bucket_addresses[_]
	not has_tls_deny(bucket)
	msg := sprintf(
		"[HIPAA 164.312(e)(1) / GAP-03] %s: no bucket policy denying non-TLS. Remediation: Deny s3:* when aws:SecureTransport is false.",
		[bucket],
	)
}

# Evidence / CloudTrail buckets also need TLS; enforce on every S3 bucket.
app_bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_tls_deny(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	policy_mentions_secure_transport(r)
}

policy_mentions_secure_transport(r) if {
	# jsonencode(...) shows up as a string in references/calls; also check planned_values.
	some pv in input.planned_values.root_module.resources
	pv.type == "aws_s3_bucket_policy"
	pv.name == r.name
	contains(lower(pv.values.policy), "securetransport")
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
