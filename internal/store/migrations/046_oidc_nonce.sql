-- Existing states are short-lived and cannot be safely upgraded because no
-- nonce was sent to their authorization request. Force those logins to restart.
DELETE FROM oidc_states;
ALTER TABLE oidc_states ADD COLUMN nonce text NOT NULL;
