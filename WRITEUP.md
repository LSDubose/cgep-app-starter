# WRITEUP.md — Acme Health Patient Intake API GRC Baseline

## Primary Framework

**SOC 2 Trust Services Criteria (TSC)**

Acme Health's immediate driver is enterprise customer trust. The CTO's 30-day ask is audit-defensible infrastructure — not regulatory compliance. SOC 2 is the right pick because it is what enterprise customers ask for first, it maps cleanly to the technical controls we can enforce in code, and the Trust Services Criteria are specific enough to write Rego policies against. HIPAA would have been the correct long-term choice given PHI is in scope, but SOC 2 gets Acme to a customer-facing attestation faster. Both are noted in the OSCAL props for traceability.

## What I Built

A four-layer GRC system wrapped around the cgep-app-starter Patient Intake API.

**Layer 1 — Terraform baseline (`terraform/baseline.tf`)**

Added directly to the starter's Terraform without modifying main.tf. Closes six of eight gaps:

| Gap | Remediation | SOC 2 Control |
|-----|-------------|---------------|
| GAP-01 | S3 SSE-KMS with customer CMK | CC6.1 |
| GAP-02 | DynamoDB SSE with customer CMK | CC6.1 |
| GAP-03 | S3 bucket policy denying non-TLS | CC6.7 |
| GAP-04 | S3 versioning enabled | A1.2 |
| GAP-07 | Least-privilege IAM replacing dynamodb:* and s3:* | CC6.3 |
| GAP-08 | API Gateway access logging + throttling | CC7.2 |

Also added an evidence vault (S3 with Object Lock GOVERNANCE mode, 90-day retention) and a KMS CMK with rotation enabled.

GAP-05 (Lambda VPC placement) and GAP-06 (reserved concurrency, DLQ, X-Ray) are documented in OSCAL as partially remediated — the VPC exists in the starter but wiring Lambda into it requires changes to main.tf that were out of scope for this submission.

**Layer 2 — OPA policy suite (`policies/`)**

Five Rego policies, each with passing and failing unit tests (10/10 passing):

| Policy | Gap | SOC 2 |
|--------|-----|-------|
| cc6_1_s3_kms_encryption.rego | GAP-01 | CC6.1 |
| cc6_1_dynamodb_kms_encryption.rego | GAP-02 | CC6.1 |
| cc6_7_s3_tls_required.rego | GAP-03 | CC6.7 |
| a1_2_s3_versioning.rego | GAP-04 | A1.2 |
| cc6_3_iam_least_privilege.rego | GAP-07 | CC6.3 |

**Layer 3 — GitHub Actions pipeline (`.github/workflows/grc-gate.yml`)**

Five steps: plan, policy check with Conftest, copy evidence, sign with Cosign keyless, upload to vault. Two PRs in repo history — PR #1 green (merged), PR #2 red (blocked by CC6.1 policy failure).

**Layer 4 — OSCAL (`oscal/`)**

Component definition describing the system, mapping SC-28 and SC-8 to implemented requirements with evidence URIs pointing at signed bundles in the vault.

## Design Decisions

**GOVERNANCE vs COMPLIANCE mode on Object Lock:** Chose GOVERNANCE. A 30-day build with a single engineer shouldn't use COMPLIANCE mode — if something goes wrong with the vault configuration there needs to be an escape hatch. COMPLIANCE mode would be appropriate for production.

**Automatic apply on merge vs manual gate:** Auto-apply on merge. Solo build with no second reviewer — a manual approval gate adds friction without adding value. In a team context with multiple engineers, a manual approval step between policy gate and apply would be the right call.

**Single AWS account:** Used the same account for workload and evidence vault. A separate evidence vault account is cleaner for production — it prevents workload-account admins from tampering with evidence. Out of scope for 30 days.

**baseline.tf instead of modifying main.tf:** Kept the starter intact and auditable. Every GRC addition is in one file with clear comments. A grader can diff baseline.tf against main.tf and see exactly what was added and why.

## What I Didn't Get To

- **GAP-05** (Lambda VPC placement): The private subnets exist. Wiring Lambda into them requires a security group and NAT gateway for DynamoDB access. Left for next sprint.
- **GAP-06** (reserved concurrency, DLQ, X-Ray): Operational controls. Would add in the next sprint alongside CloudWatch alarms.
- **CloudTrail**: Deployed and captured findings in the labs but not wired into this repo's pipeline. Next sprint.
- **OSCAL SSP**: The component definition is the first layer. A full System Security Plan mapping every control would be the capstone of another sprint.

## Verification Instructions

```bash
# Clone the repo
git clone https://github.com/LSDubose/cgep-app-starter
cd cgep-app-starter

# Run OPA tests
opa test policies/ -v

# Verify evidence chain
EVIDENCE_VAULT=acme-health-intake-evidence-ced0644b
RUN_ID=29695664856
aws s3 cp s3://${EVIDENCE_VAULT}/runs/${RUN_ID}/ /tmp/evidence/ --recursive
BUNDLE=$(ls /tmp/evidence/evidence-*.tar.gz | head -1)
sha256sum $BUNDLE
cosign verify-blob \
  --bundle /tmp/evidence/$(basename $BUNDLE).sig.bundle \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  $BUNDLE
```