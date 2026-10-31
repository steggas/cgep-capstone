# Acme Health Capstone — Design (Week 1)

Spine for `WRITEUP.md`. Decisions below are the ones the brief requires us to defend.

## Primary framework: HIPAA Security Rule

Acme is a telehealth company whose Patient Intake API stores PHI. HIPAA is the only one of the three options whose obligation is triggered by the data class itself, not by a customer questionnaire or a federal pilot that may never close. SOC 2 and CMMC stay as secondary mappings in OSCAL `props` where the same technical control satisfies them; every Rego policy and every `control-implementation.source` cites HIPAA (via NIST SP 800-66 Rev. 2 as the OSCAL catalog, with 164.x IDs as props).

## Gap map

| Gap | Close in Terraform | Enforce in Rego | HIPAA control(s) |
|---|---|---|---|
| GAP-01 S3 SSE-S3 → CMK | Yes — `aws_s3_bucket_server_side_encryption_configuration` on uploads with our CMK | Yes — deny plans without `aws:kms` + key | 164.312(a)(2)(iv) |
| GAP-02 DynamoDB default key → CMK | Yes — `server_side_encryption { kms_key_arn = ... }` | Yes | 164.312(a)(2)(iv) |
| GAP-03 No TLS-only bucket policy | Yes — `aws:SecureTransport` deny | Yes | 164.312(e)(1) |
| GAP-04 No S3 versioning | Yes — versioning enabled | Yes | 164.308(a)(7) |
| GAP-05 Lambda outside VPC | Yes — `vpc_config` on private subnets + SG | Yes | 164.312(e)(1) |
| GAP-06 No concurrency / DLQ / X-Ray | Partial — DLQ only (reserved concurrency blocked by account unreserved floor of 10) | Optional policy if we add concurrency later | 164.308(a)(1) / secondary SOC 2 CC7.2 |
| GAP-07 `dynamodb:*` / `s3:*` | Yes — least-privilege actions only | Yes — deny `*` on data stores | 164.312(a)(1) |
| GAP-08 No API access logging / throttle | Yes — access logs + default route throttle | Yes — require `access_log_settings` | 164.312(b) |

Five deepest policies for the grader's re-introduce test: GAP-01, GAP-02, GAP-03, GAP-05, GAP-07. GAP-04 and GAP-08 also get policies; GAP-06 is Terraform-first with a lighter policy.

## Design decisions

| Decision | Choice | Trade-off accepted |
|---|---|---|
| Region | `us-east-1` | Matches lab account and existing OIDC/vault patterns; no residency requirement in the brief. |
| Object Lock mode | **GOVERNANCE**, 30-day retention | Strong enough for chain-of-custody demos; account admins can still clean up after the 30-day project. Production would use COMPLIANCE + longer retention. |
| Apply | Auto-apply on merge to `main` after the Conftest gate | Trusts the gate; blast radius limited to this sandbox account. A real prod rollout would add an environment approval. |
| Account model | **Single account** for workload + vault | Acceptable for 30 days per the brief. Production: vault in a separate evidence account so compromise of the workload account cannot rewrite history. |
| Terraform vs policy | Fix all eight gaps in Terraform; five+ Rego policies so a re-introduced gap fails the PR | Terraform is the floor; policy is the tripwire that keeps it closed. |

## Layer sketch (assembly from labs)

| Layer | Capstone path | Lab source |
|---|---|---|
| 1 Terraform | `terraform/kms.tf`, `evidence-vault.tf`, `cloudtrail.tf`, `oidc-trust.tf`, `hardening.tf` + starter `main.tf` | 2.3 / 2.4 / 2.5 / 4.3 / 5.2 |
| 2 Rego | `policies/*.rego` + `policies/tests/` | 3.3 / 3.4 |
| 3 Pipeline | `.github/workflows/grc-gate.yml` (plan → check → apply → sign → upload) | 4.3 + 4.4 |
| 4 OSCAL | `oscal/components/acme-intake.json` + profile | 6.1, HIPAA controls |

## Out of scope (named for the write-up)

- Cognito / API auth (WORKLOAD.md)
- Multi-region failover
- Patient data lifecycle (deletion / export)
- Separate evidence account
- COMPLIANCE Object Lock mode
