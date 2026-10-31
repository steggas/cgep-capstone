package compliance.hipaa_test

import rego.v1
import data.compliance.hipaa.s3_cmk as s3_cmk
import data.compliance.hipaa.ddb_cmk as ddb_cmk
import data.compliance.hipaa.tls_transit as tls
import data.compliance.hipaa.lambda_vpc as vpc
import data.compliance.hipaa.least_privilege as lp
import data.compliance.hipaa.s3_versioning as ver

# --- GAP-01 S3 CMK ---

test_s3_cmk_fail if {
	count(s3_cmk.deny) > 0 with input as {
		"configuration": {"root_module": {"resources": [{
			"type": "aws_s3_bucket",
			"name": "uploads",
		}]}},
	}
}

test_s3_cmk_pass if {
	count(s3_cmk.deny) == 0 with input as {
		"configuration": {"root_module": {"resources": [
			{"type": "aws_s3_bucket", "name": "uploads"},
			{
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"name": "uploads",
				"expressions": {
					"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
					"rule": [{"apply_server_side_encryption_by_default": [{
						"sse_algorithm": {"constant_value": "aws:kms"},
					}]}],
				},
			},
		]}},
	}
}

# --- GAP-02 DynamoDB CMK ---

test_ddb_cmk_fail if {
	count(ddb_cmk.deny) > 0 with input as {
		"configuration": {"root_module": {"resources": [{
			"type": "aws_dynamodb_table",
			"name": "intake",
			"expressions": {},
		}]}},
	}
}

test_ddb_cmk_pass if {
	count(ddb_cmk.deny) == 0 with input as {
		"configuration": {"root_module": {"resources": [{
			"type": "aws_dynamodb_table",
			"name": "intake",
			"expressions": {
				"server_side_encryption": [{
					"enabled": {"constant_value": true},
					"kms_key_arn": {"references": ["aws_kms_key.phi.arn"]},
				}],
			},
		}]}},
	}
}

# --- GAP-03 TLS ---

test_tls_fail if {
	count(tls.deny) > 0 with input as {
		"configuration": {"root_module": {"resources": [{
			"type": "aws_s3_bucket",
			"name": "uploads",
		}]}},
		"planned_values": {"root_module": {"resources": []}},
	}
}

test_tls_pass if {
	count(tls.deny) == 0 with input as {
		"configuration": {"root_module": {"resources": [
			{"type": "aws_s3_bucket", "name": "uploads"},
			{
				"type": "aws_s3_bucket_policy",
				"name": "uploads",
				"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
			},
		]}},
		"planned_values": {"root_module": {"resources": [{
			"type": "aws_s3_bucket_policy",
			"name": "uploads",
			"values": {"policy": "{\"Statement\":[{\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"},
		}]}},
	}
}

# --- GAP-05 Lambda VPC ---

test_vpc_fail if {
	count(vpc.deny) > 0 with input as {
		"configuration": {"root_module": {"resources": [{
			"type": "aws_lambda_function",
			"name": "intake",
			"expressions": {},
		}]}},
	}
}

test_vpc_pass if {
	count(vpc.deny) == 0 with input as {
		"configuration": {"root_module": {"resources": [{
			"type": "aws_lambda_function",
			"name": "intake",
			"expressions": {"vpc_config": [{"subnet_ids": {"references": ["aws_subnet.private"]}}]},
		}]}},
	}
}

# --- GAP-07 least privilege ---

test_lp_fail if {
	count(lp.deny) > 0 with input as {
		"planned_values": {"root_module": {"resources": [{
			"type": "aws_iam_role_policy",
			"name": "lambda_inline",
			"values": {"policy": "{\"Statement\":[{\"Action\":\"dynamodb:*\",\"Effect\":\"Allow\"}]}"},
		}]}},
	}
}

test_lp_pass if {
	count(lp.deny) == 0 with input as {
		"planned_values": {"root_module": {"resources": [{
			"type": "aws_iam_role_policy",
			"name": "lambda_inline",
			"values": {"policy": "{\"Statement\":[{\"Action\":[\"dynamodb:PutItem\"],\"Effect\":\"Allow\"}]}"},
		}]}},
	}
}

# --- GAP-04 versioning ---

test_ver_fail if {
	count(ver.deny) > 0 with input as {
		"configuration": {"root_module": {"resources": [{
			"type": "aws_s3_bucket",
			"name": "uploads",
		}]}},
	}
}

test_ver_pass if {
	count(ver.deny) == 0 with input as {
		"configuration": {"root_module": {"resources": [
			{"type": "aws_s3_bucket", "name": "uploads"},
			{
				"type": "aws_s3_bucket_versioning",
				"name": "uploads",
				"expressions": {
					"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
					"versioning_configuration": [{"status": {"constant_value": "Enabled"}}],
				},
			},
		]}},
	}
}
