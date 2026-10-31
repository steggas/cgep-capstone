# METADATA
# title: HIPAA 164.308(a)(7) — S3 versioning for PHI recovery
# description: "Uploads bucket must enable versioning (GAP-04)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.308(a)(7)"
#   severity: medium
#   remediation: "Add aws_s3_bucket_versioning with status = Enabled."
#   gap: GAP-04
package compliance.hipaa.s3_versioning

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_versioning(bucket)
	msg := sprintf(
		"[HIPAA 164.308(a)(7) / GAP-04] %s: missing versioning. Remediation: aws_s3_bucket_versioning { status = Enabled }.",
		[bucket],
	)
}

# Only the workload uploads bucket is required for contingency; name contains "uploads".
bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	contains(r.name, "uploads")
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_versioning(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	some cfg in r.expressions.versioning_configuration
	cfg.status.constant_value == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
