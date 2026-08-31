# Production certification

Stable promotion requires evidence from the real infrastructure boundaries that
disposable CI cannot reproduce. Run the release workflow through its candidate
stage, exercise the exact signed candidate digest, and then dispatch the
`Production certification` workflow on the same Git commit. The
`production-certification` GitHub environment must have required reviewers;
without a successful signed certification artifact, promotion fails closed.
The candidate package remains private until promotion, so staging hosts need a
read-only GHCR credential while exercising the digest.

Configure two protected GitHub environments before the first release:

1. `production-certification`, whose reviewers confirm that the submitted
   evidence matches the external systems and named owners.
2. `production-release`, whose distinct reviewers approve stable tagging only
   after the certification workflow succeeds.

Start `Release image` and wait for its candidate job to finish. The job summary
shows the exact digest. Exercise that digest, dispatch `Production
certification` on the exact same tag or commit with the digest and JSON below,
approve its environment, and only then approve `production-release`. Promotion
locates the newest successful certification for the same commit, verifies its
Sigstore identity, validates it against the candidate digest and current time,
and re-verifies all automated evidence. If promotion ran before certification
was available, create the certification and rerun only the failed promotion
job; the candidate is not rebuilt or retagged.

Submit a JSON object using schema version 1. The workflow overwrites
`sourceCommit`, `candidateImage`, `createdAt`, and `expiresAt` with its selected
Git ref, input digest, signing time, and chosen lifetime, validates the document
with the Go release-evidence validator, verifies the
candidate image's release-workflow signature, and signs the canonical result
with GitHub OIDC. Before signing, and again immediately before promotion, the
workflow downloads every referenced artifact through the private-network
egress guard and verifies its bytes against the declared SHA-256. Each download
is limited to 64 MiB. Evidence URLs must be stable, credential-free HTTPS URLs
with no query string or fragment. Redirects must remain credential-free HTTPS
destinations. Every referenced artifact includes its lowercase SHA-256 so later
reviewers can detect replacement.

```json
{
  "schemaVersion": 1,
  "environment": "production-eu",
  "owner": "release-manager@example.com",
  "gates": {
    "external-integrations": {
      "owner": "identity-and-delivery-team",
      "completedAt": "2026-08-30T10:00:00Z",
      "evidence": [{"name":"provider conformance","url":"https://evidence.example.com/releases/v1/providers.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
    },
    "production-data-upgrade": {
      "owner": "database-team",
      "completedAt": "2026-08-30T10:00:00Z",
      "evidence": [{"name":"upgrade report","url":"https://evidence.example.com/releases/v1/upgrade.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
    },
    "production-storage-recovery": {
      "owner": "database-team",
      "completedAt": "2026-08-30T10:00:00Z",
      "evidence": [{"name":"RPO and RTO report","url":"https://evidence.example.com/releases/v1/recovery.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
    },
    "multi-host-swarm": {
      "owner": "platform-team",
      "completedAt": "2026-08-30T10:00:00Z",
      "evidence": [{"name":"partition exercise","url":"https://evidence.example.com/releases/v1/swarm.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
    },
    "hardening-review": {
      "owner": "security-reviewer@example.com",
      "completedAt": "2026-08-30T10:00:00Z",
      "evidence": [{"name":"independent assessment","url":"https://evidence.example.com/releases/v1/hardening.pdf","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
    },
    "control-plane-recovery": {
      "owner": "platform-team",
      "completedAt": "2026-08-30T10:00:00Z",
      "evidence": [{"name":"disaster recovery report","url":"https://evidence.example.com/releases/v1/control-plane.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
    },
    "live-dokploy-cutover": {
      "owner": "migration-team",
      "completedAt": "2026-08-30T10:00:00Z",
      "evidence": [{"name":"cutover verification","url":"https://evidence.example.com/releases/v1/cutover.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
    },
    "production-topology-soak": {
      "owner": "release-manager@example.com",
      "completedAt": "2026-08-30T11:00:00Z",
      "evidence": [{"name":"candidate soak","url":"https://evidence.example.com/releases/v1/soak.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
    }
  }
}
```

Certifications are valid for at most 31 days, and every gate must have completed
within 30 days of certification. The eight gate names are fixed so a typo or an
invented substitute cannot silently pass. `external-integrations` covers the
configured Entra ID, Okta, Google Workspace, object storage, registry,
notification, and model-gateway boundaries; record `not applicable` decisions
inside the referenced report rather than omitting the gate.
