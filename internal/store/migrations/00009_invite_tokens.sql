-- 00009_invite_tokens.sql
-- Invite-first-login (spec §79): single-use tokens that let an invited user
-- set their own password and claim their organization membership on first
-- login, instead of admins handing out credentials. Only the SHA-256 hash of
-- the token is stored, so the raw token is shown exactly once at issue time.

-- +goose Up
CREATE TABLE invite_tokens (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash      text NOT NULL,
    role            text NOT NULL DEFAULT 'member'
                    CHECK (role IN ('owner', 'admin', 'member')),
    invited_by      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at      timestamptz NOT NULL,
    accepted_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT invite_tokens_hash_key UNIQUE (token_hash)
);

CREATE INDEX idx_invite_tokens_org ON invite_tokens (organization_id);
CREATE INDEX idx_invite_tokens_user ON invite_tokens (user_id);

-- +goose Down
DROP TABLE IF EXISTS invite_tokens;
