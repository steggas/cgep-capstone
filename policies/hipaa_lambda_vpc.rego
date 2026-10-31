# METADATA
# title: HIPAA 164.312(e)(1) — Lambda inside VPC
# description: "Intake Lambda must set vpc_config (GAP-05)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: high
#   remediation: "Add vpc_config { subnet_ids = aws_subnet.private[*].id, security_group_ids = [aws_security_group.lambda.id] }."
#   gap: GAP-05
package compliance.hipaa.lambda_vpc

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	not has_vpc_config(r)
	msg := sprintf(
		"[HIPAA 164.312(e)(1) / GAP-05] aws_lambda_function.%s: missing vpc_config. Remediation: place the function in the starter VPC private subnets.",
		[r.name],
	)
}

has_vpc_config(r) if {
	count(r.expressions.vpc_config) > 0
}
