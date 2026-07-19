# Acme Health Patient Intake API — GRC Capstone

**Primary framework:** SOC 2 Trust Services Criteria  
**Submitted by:** LaMeisha DuBose  
**Commit SHA:** 5c0e1c20d1a0e3b7c2967541fe976487aeb38e05

## What's in this repo

| Path | What it is |
|------|-----------|
| `terraform/main.tf` | Original starter — untouched |
| `terraform/baseline.tf` | GRC baseline closing GAP-01, 02, 03, 04, 07, 08 |
| `policies/` | 5 SOC 2 Rego policies with unit tests |
| `.github/workflows/grc-gate.yml` | CI gate — plan, policy check, sign, upload |
| `oscal/` | OSCAL component definition |
| `WRITEUP.md` | Design decisions and trade-offs |

## Verify the policy suite

```bash
opa test policies/ -v
```

Expected: 10/10 PASS

## Verify the evidence chain

```bash
EVIDENCE_VAULT=acme-health-intake-evidence-ced0644b
RUN_ID=29695664856
mkdir -p /tmp/evidence
aws s3 cp s3://${EVIDENCE_VAULT}/runs/${RUN_ID}/ /tmp/evidence/ --recursive
BUNDLE=$(ls /tmp/evidence/evidence-*.tar.gz | head -1)
cosign verify-blob \
  --bundle /tmp/evidence/$(basename $BUNDLE).sig.bundle \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  $BUNDLE
```

Expected: `Verified OK`

## PR history

- PR #1 — green, all policies pass, merged
- PR #2 — red, CC6.1 fired on missing S3 KMS encryption, blocked
