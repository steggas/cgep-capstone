# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

**HIPAA Security Rule.** Acme is a telehealth company whose Patient Intake API stores PHI. HIPAA is the only option of the three whose obligation is triggered by the data class itself — not by a customer questionnaire (SOC 2) or a federal pilot that may never close (CMMC). SOC 2 TSC and CMMC L2 remain useful secondary mappings for the same technical controls; every Rego metadata block and the OSCAL `control-implementation.source` cite HIPAA (NIST SP 800-66 Rev. 2 as the catalog URI, with 164.x IDs in props).

## Control coverage

| Gap | Closed in Terraform | Enforced in Rego | HIPAA control |
|---|---|---|---|
| GAP-01 S3 SSE → CMK | `aws_s3_bucket_server_side_encryption_configuration.uploads` + `aws_kms_key.phi` | `compliance.hipaa.s3_cmk` | 164.312(a)(2)(iv) |
| GAP-02 DynamoDB CMK | `server_side_encryption` on `aws_dynamodb_table.intake` | `compliance.hipaa.ddb_cmk` | 164.312(a)(2)(iv) |
| GAP-03 TLS-only S3 | bucket policies with `aws:SecureTransport` deny | `compliance.hipaa.tls_transit` | 164.312(e)(1) |
| GAP-04 versioning | `aws_s3_bucket_versioning.uploads` | `compliance.hipaa.s3_versioning` | 164.308(a)(7) |
| GAP-05 Lambda VPC | `vpc_config` + private RT + S3/DDB endpoints | `compliance.hipaa.lambda_vpc` | 164.312(e)(1) |
| GAP-06 DLQ / concurrency | DLQ only (reserved concurrency blocked by account unreserved floor of 10) | — | resilience / secondary SOC 2 CC7.2 |
| GAP-07 wild IAM | least-privilege inline policy | `compliance.hipaa.least_privilege` | 164.312(a)(1) |
| GAP-08 API logs / throttle | `access_log_settings` + default route throttle | — (document; Terraform floor) | 164.312(b) |

## Design decisions

| Decision | Choice | Trade-off |
|---|---|---|
| Region | `us-east-1` | Matches the lab account; no residency requirement in the brief. |
| Object Lock | **GOVERNANCE**, 30 days | Tamper-resistant for the grader's verify script; privileged cleanup still possible after the 30-day project. Production would use COMPLIANCE + longer retention. |
| Apply | Auto-apply on merge to `main` after Conftest | Continuous; blast radius is this sandbox. A real rollout would add an environment approval. |
| Accounts | Single account for workload + vault | Acceptable for 30 days. Production: vault in a separate evidence account. |
| Terraform vs policy | Fix gaps in Terraform; six Rego policies as the tripwire | Terraform is the floor; policy keeps it closed (grader re-introduces a gap — see red PR #3). |

## How the pipeline produces evidence

1. PR opened → `grc-gate` Plans Terraform against remote state (`acme-capstone-tfstate-steggas`).
2. **Policy check** runs `scripts/policy-gate.sh` (six HIPAA namespaces). Fail closed.
3. On **push to main**, **Apply** runs the same plan.
4. **Sign** Cosign-keyless (GitHub OIDC) over the plan + Conftest JSON bundle.
5. **Upload** to `s3://acme-health-evidence-a40865c5/runs/<run_id>/` with Object Lock.

Assessor verification (already run locally):

```bash
scripts/verify-evidence.sh 41187275501 --vault acme-health-evidence-a40865c5 --profile default
# → Verified OK / CHAIN INTACT for run 41187275501
```

Green history: [PR #1](https://github.com/steggas/cgep-capstone/pull/1), [PR #2](https://github.com/steggas/cgep-capstone/pull/2) (merged).  
Red history: [PR #3](https://github.com/steggas/cgep-capstone/pull/3) — GAP-05 re-introduced; gate failed; left open on purpose.

## Trade-offs and what I'd do with another sprint

- **Reserved concurrency** for GAP-06 lost to the account's unreserved floor of 10; keep DLQ, add concurrency when the account quota allows.
- **Remote state** is a plain versioned bucket, not Object Lock — correct for mutable state, but I'd document break-glass separately.
- **OIDC role** uses PowerUserAccess for apply; next sprint: least-privilege Terraform deploy policy.
- **Self-merge on a solo repo** is an SoD gap a real program would not accept.

## What I didn't get to

- Cognito / API authentication (explicitly out of scope in `WORKLOAD.md`)
- Separate evidence account
- COMPLIANCE Object Lock mode
- Patient data lifecycle (deletion / export)
- X-Ray tracing for GAP-06
- Rego policy specifically for GAP-08 (closed in Terraform only)
