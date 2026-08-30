# Agent certificate-authority rotation

Rotate the remote-agent CA without disconnecting clusters by using a bounded
dual-trust deployment. Docker secrets are immutable, so every replacement CA,
key, listener certificate, and listener key must use a new versioned secret
name. Keep the old secrets until the rollback window has closed.

This procedure assumes the current credentials are named with a `v1` suffix
and the replacements use `v2`. Substitute the names actually deployed in the
stack. Run every installer invocation from the same reviewed release checkout
and use the same immutable image digests and control-plane secret files as the
current installation.

## Preconditions

- Back up PostgreSQL and escrow the current master key, both CA generations,
  and both listener identities in the normal protected recovery store.
- Confirm every active or draining cluster has heartbeated recently. An
  offline cluster cannot receive the broadened trust bundle and must not be
  silently excluded from the migration decision.
- Generate a self-signed signing CA and matching private key, then generate a
  listener certificate for `DOCKYARD_AGENT_HOST` signed by that new CA. Protect
  every private-key file with mode `0600`.
- Record the new CA fingerprint in the same form returned by the API:

```sh
NEW_CA_FINGERPRINT=$(openssl x509 -in /secure/pki/agent-ca-v2.crt -outform DER \
  | openssl dgst -sha256 -r | awk '{print "sha256:" tolower($1)}')
printf '%s\n' "$NEW_CA_FINGERPRINT"
```

Do not continue if the old CA or listener certificate expires before the
planned migration and rollback windows end.

## Phase 1: publish dual trust and change the signer

Keep serving the old listener certificate. Make the new CA the active signer
and mount the old CA as the previous authority through the temporary rollover
overlay:

```sh
export DOCKYARD_INSTALL_MODE=ha
export DOCKYARD_REUSE_EXISTING_SECRETS=true
export DOCKYARD_AGENT_HOST=agents.dockyard.example.com

export DOCKYARD_AGENT_CA_CERT_FILE=/secure/pki/agent-ca-v2.crt
export DOCKYARD_AGENT_CA_KEY_FILE=/secure/pki/agent-ca-v2.key
export DOCKYARD_AGENT_SERVER_CERT_FILE=/secure/pki/agent-server-v1.crt
export DOCKYARD_AGENT_SERVER_KEY_FILE=/secure/pki/agent-server-v1.key
export DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE=/secure/pki/agent-ca-v1.crt

export DOCKYARD_AGENT_CA_CERT_SECRET=dockyard_agent_ca_cert_v2
export DOCKYARD_AGENT_CA_KEY_SECRET=dockyard_agent_ca_key_v2
export DOCKYARD_AGENT_SERVER_CERT_SECRET=dockyard_agent_server_cert_v1
export DOCKYARD_AGENT_SERVER_KEY_SECRET=dockyard_agent_server_key_v1
export DOCKYARD_AGENT_PREVIOUS_CA_CERT_SECRET=dockyard_agent_ca_cert_v1

DOCKYARD_INSTALL_DRY_RUN=true scripts/install-swarm.sh
scripts/install-swarm.sh
```

The installer verifies that the active and previous CAs differ and that the
old listener still chains to one of them. Controllers then accept client
certificates from either CA, issue all new certificates from v2, and return the
authenticated trust bundle on every heartbeat. A current agent first persists
that bundle and then atomically replaces its identity with a v2 certificate.
Older agents ignore the heartbeat response body, so they remain connected but
do not migrate; upgrade them before continuing.

List clusters with an owner or administrator token and wait until every active
or draining cluster reports the exact new fingerprint with no pending
fingerprint:

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $DOCKYARD_TOKEN" \
  -H "X-Organization-ID: $DOCKYARD_ORGANIZATION_ID" \
  https://dockyard.example.com/v1/clusters \
  | jq -e --arg expected "$NEW_CA_FINGERPRINT" '
      [.items[] | select(.state == "active" or .state == "draining")] as $clusters
      | ($clusters | length) > 0
        and all($clusters[];
          .certificateAuthorityFingerprint == $expected
          and (.pendingCertificateAuthorityFingerprint // "") == "")'
```

Also require fresh `lastSeenAt` values. Investigate, upgrade, re-enroll, disable,
or remove every exception explicitly. Never remove v1 trust merely because a
timeout elapsed.

## Phase 2: replace the listener identity

After every managed cluster reports v2, repeat the installer with the listener
certificate and key changed to v2 while keeping the previous-CA file and
rollover overlay configured:

```sh
export DOCKYARD_AGENT_SERVER_CERT_FILE=/secure/pki/agent-server-v2.crt
export DOCKYARD_AGENT_SERVER_KEY_FILE=/secure/pki/agent-server-v2.key
export DOCKYARD_AGENT_SERVER_CERT_SECRET=dockyard_agent_server_cert_v2
export DOCKYARD_AGENT_SERVER_KEY_SECRET=dockyard_agent_server_key_v2

DOCKYARD_INSTALL_DRY_RUN=true scripts/install-swarm.sh
scripts/install-swarm.sh
```

Wait for controller convergence, then require a fresh heartbeat from every
active or draining cluster. Check that the `agent_ca`, `agent_previous_ca`, and
`agent_server` control-plane certificate-expiry metrics reflect the intended
certificates.

## Phase 3: retire the old CA

Remove `DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE` from the environment and run the
installer again. This renders only `swarm.yml` and `swarm-ha.yml`, so the
temporary `swarm-agent-ca-rollover.yml` overlay and old trust mount disappear.
Keep all v2 secret-name variables set.

```sh
unset DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE
DOCKYARD_INSTALL_DRY_RUN=true scripts/install-swarm.sh
scripts/install-swarm.sh
```

Verify another fresh heartbeat from every managed cluster. The
`agent_previous_ca` expiry gauge must disappear. Retain the unreferenced v1
Docker secrets and escrowed files for the declared rollback window; remove
them only after that window and a recovery review.

## Rollback

Before retiring v1, restore the last known-good stack configuration. If any
agent already has a v2 identity, do not deploy an old-only listener. Reverse
the transition instead: make v1 the active signer, mount v2 as the previous
CA, use a listener certificate trusted by the combined bundle, and wait until
every managed cluster again reports the v1 fingerprint. This uses the same
three phases with the version names exchanged.

After v1 has been retired, rollback still requires that reverse dual-trust
procedure. If the old signing key or listener identity was destroyed, restore
forward using v2; do not weaken client-certificate verification or edit
cluster serials in PostgreSQL.
