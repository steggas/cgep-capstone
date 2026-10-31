# Capstone policy suite (HIPAA Security Rule)

Primary framework: **HIPAA Security Rule**. Each policy maps to a named gap in `GAPS.md`.

| Package | Gap | Control |
|---|---|---|
| `compliance.hipaa.s3_cmk` | GAP-01 | 164.312(a)(2)(iv) |
| `compliance.hipaa.ddb_cmk` | GAP-02 | 164.312(a)(2)(iv) |
| `compliance.hipaa.tls_transit` | GAP-03 | 164.312(e)(1) |
| `compliance.hipaa.s3_versioning` | GAP-04 | 164.308(a)(7) |
| `compliance.hipaa.lambda_vpc` | GAP-05 | 164.312(e)(1) |
| `compliance.hipaa.least_privilege` | GAP-07 | 164.312(a)(1) |

```bash
opa test ./policies -v
# from repo root, after terraform plan -out=tfplan in terraform/
./scripts/policy-gate.sh --workspace terraform
```
