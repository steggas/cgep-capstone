# METADATA
# title: HIPAA 164.312(a)(2)(iv) — DynamoDB uses customer CMK
# description: "aws_dynamodb_table must enable server_side_encryption with a CMK (GAP-02)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: "Add server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.<name>.arn }."
#   gap: GAP-02
package compliance.hipaa.ddb_cmk

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	not has_cmk(r)
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv) / GAP-02] aws_dynamodb_table.%s: missing customer CMK encryption. Remediation: server_side_encryption { enabled = true, kms_key_arn = <cmk> }.",
		[r.name],
	)
}

has_cmk(r) if {
	some block in r.expressions.server_side_encryption
	block.enabled.constant_value == true
	count(block.kms_key_arn.references) > 0
}
