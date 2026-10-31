# OSCAL (capstone Layer 4)

| Artifact | Describes | Evidence |
|---|---|---|
| `components/acme-intake.json` | Patient Intake starter + GRC baseline. Primary framework: **HIPAA Security Rule** via NIST SP 800-66 Rev. 2. | `s3://acme-health-evidence-a40865c5/runs/41187275501/` — verify with `scripts/verify-evidence.sh 41187275501 --vault acme-health-evidence-a40865c5` |
| `profiles/hipaa-minimum.json` | Selects the five HIPAA controls the component implements. | Authoring only. |

```bash
# If compliance-trestle is installed:
trestle validate -f oscal/components/acme-intake.json
trestle validate -f oscal/profiles/hipaa-minimum.json
```
