# METADATA
# title: HIPAA 164.312(a)(1) — no wildcard data-store IAM
# description: "Lambda inline policies must not grant dynamodb:* or s3:* (GAP-07)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(1)"
#   severity: high
#   remediation: "Replace dynamodb:* / s3:* with the specific actions the handler needs."
#   gap: GAP-07
package compliance.hipaa.least_privilege

import rego.v1

deny contains msg if {
	some pv in input.planned_values.root_module.resources
	pv.type == "aws_iam_role_policy"
	action := actions(pv.values.policy)[_]
	is_wildcard_data_action(action)
	msg := sprintf(
		"[HIPAA 164.312(a)(1) / GAP-07] aws_iam_role_policy.%s: grants %s. Remediation: replace wildcards with least-privilege actions.",
		[pv.name, action],
	)
}

actions(policy_str) := acts if {
	doc := json.unmarshal(policy_str)
	acts := [a |
		some stmt in doc.Statement
		some a in as_array(stmt.Action)
	]
}

as_array(x) := x if is_array(x)
as_array(x) := [x] if is_string(x)

is_wildcard_data_action(a) if a == "dynamodb:*"
is_wildcard_data_action(a) if a == "s3:*"
is_wildcard_data_action(a) if a == "*"
