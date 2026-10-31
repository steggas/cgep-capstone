# cgep-capstone — Acme Health Patient Intake (CGE-P)

Fork of [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter). Primary framework: **HIPAA Security Rule**. Design spine: [`DESIGN.md`](DESIGN.md). Graded reasoning: [`WRITEUP.md`](WRITEUP.md).

## Grader verification

```bash
# 1. Identity / vault
aws sts get-caller-identity
# Evidence vault: acme-health-evidence-a40865c5
# Gate role:     arn:aws:iam::758496865249:role/cgep-capstone-grc-gate

# 2. Chain of custody (signed main run)
./scripts/verify-evidence.sh 41187275501 --vault acme-health-evidence-a40865c5
# expect: Verified OK / CHAIN INTACT

# 3. Policy suite
opa test ./policies -v
# from a planned workspace:
./scripts/policy-gate.sh --workspace terraform

# 4. OSCAL
trestle validate -f oscal/components/acme-intake.json
```

Green PRs: #1 (baseline), #2 (OIDC plan fix). Red PR left open: #3 (GAP-05 re-introduced).

## Layout

```
terraform/          # starter workload + kms / evidence-vault / cloudtrail / oidc / hardening
policies/           # six HIPAA Rego packages + tests
scripts/            # policy-gate.sh, verify-evidence.sh, capture-evidence.sh
.github/workflows/  # grc-gate.yml — Plan → Policy → Apply(main) → Sign → Upload
oscal/              # component + HIPAA profile
```

## Deploy the workload (step zero)

```bash
make creds AWS_PROFILE=default
make deploy AWS_PROFILE=default
make test   AWS_PROFILE=default
```

Destroy when finished exploring: `make destroy AWS_PROFILE=default` (after evidence is captured).
