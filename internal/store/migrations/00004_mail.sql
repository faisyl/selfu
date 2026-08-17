-- 00004_mail.sql
-- Phase 4 (G4): mail subsystem — chasquid-owned MTA state modelled as
-- platform resources (spec §26, §30–31, §37, §49, tables §85, §86).

-- +goose Up
CREATE TABLE mail_domains (
    id              uuid PRIMARY KEY,
    domain_id       uuid NOT NULL UNIQUE REFERENCES domains (id) ON DELETE CASCADE,
    status          text NOT NULL DEFAULT 'provisioning'
                    CHECK (status IN ('provisioning', 'active', 'disabled')),
    inbound_status  text NOT NULL DEFAULT 'not_configured',
    outbound_status text NOT NULL DEFAULT 'not_configured',
    tls_status      text NOT NULL DEFAULT 'not_configured',
    dkim_status     text NOT NULL DEFAULT 'not_configured',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- A mail identity is a capability of a platform user (or later, an
-- application), not a separate human identity (spec §30).
CREATE TABLE mail_identities (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id          uuid REFERENCES users (id) ON DELETE CASCADE,
    domain_id        uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    local_part       text NOT NULL,
    address          text NOT NULL,
    chasquid_username text NOT NULL,
    status           text NOT NULL DEFAULT 'requested'
                     CHECK (status IN ('requested', 'provisioning', 'active', 'suspended', 'deleted')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT mail_identity_addr_key UNIQUE (address),
    CONSTRAINT mail_identity_domain_local_key UNIQUE (domain_id, local_part)
);
CREATE INDEX idx_mail_identities_org ON mail_identities (organization_id);
CREATE INDEX idx_mail_identities_user ON mail_identities (user_id);

-- SMTP credentials: independent from authentik passwords (spec §35); the
-- platform stores only a fingerprint of the secret (spec §62) and returns
-- the secret exactly once at creation.
CREATE TABLE mail_credentials (
    id              uuid PRIMARY KEY,
    mail_identity_id uuid NOT NULL REFERENCES mail_identities (id) ON DELETE CASCADE,
    secret_fingerprint text NOT NULL,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    rotated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_mail_credentials_identity ON mail_credentials (mail_identity_id);

CREATE TABLE mail_aliases (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id       uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    local_part      text NOT NULL,
    address         text NOT NULL,
    destinations    jsonb NOT NULL DEFAULT '[]'::jsonb,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT mail_alias_addr_key UNIQUE (address),
    CONSTRAINT mail_alias_domain_local_key UNIQUE (domain_id, local_part)
);
CREATE INDEX idx_mail_aliases_org ON mail_aliases (organization_id);

-- Sender authorization: what a credential may use as MAIL FROM (spec §49).
-- Enforced by the chasquid post-data hook (G4b).
CREATE TABLE mail_submission_policies (
    id                    uuid PRIMARY KEY,
    mail_identity_id      uuid NOT NULL REFERENCES mail_identities (id) ON DELETE CASCADE,
    credential_id         uuid NOT NULL REFERENCES mail_credentials (id) ON DELETE CASCADE,
    allowed_from_addresses text[] NOT NULL DEFAULT '{}',
    allowed_from_domains  text[] NOT NULL DEFAULT '{}',
    application_instance_id uuid,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_mail_policies_credential ON mail_submission_policies (credential_id);

-- +goose Down
DROP TABLE IF EXISTS mail_submission_policies;
DROP TABLE IF EXISTS mail_aliases;
DROP TABLE IF EXISTS mail_credentials;
DROP TABLE IF EXISTS mail_identities;
DROP TABLE IF EXISTS mail_domains;