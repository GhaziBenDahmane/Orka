CREATE TABLE organization_invitations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner','admin','developer','viewer')),
    token_hash bytea NOT NULL UNIQUE,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    accepted_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (email = lower(email)),
    CHECK (NOT (accepted_at IS NOT NULL AND revoked_at IS NOT NULL)),
    CHECK ((accepted_at IS NULL AND accepted_user_id IS NULL) OR
           (accepted_at IS NOT NULL AND accepted_user_id IS NOT NULL))
);

CREATE UNIQUE INDEX organization_invitations_pending_email_idx
    ON organization_invitations(organization_id,email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX organization_invitations_expiry_idx
    ON organization_invitations(expires_at)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
