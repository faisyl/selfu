-- 00003_domains.sql
-- Phase 3 (G3): domains, hostnames, DNS provider registry and verification
-- logs (spec §10–§12, §22, tables §85).

-- +goose Up
CREATE TABLE domains (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    fqdn               text NOT NULL,
    status             text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'verification_required', 'verified', 'suspended')),
    verification_method text NOT NULL DEFAULT 'dns_txt',
    verification_token text NOT NULL DEFAULT '',
    verified_at        timestamptz,
    web_enabled        boolean NOT NULL DEFAULT false,
    mail_enabled       boolean NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT domains_org_fqdn_key UNIQUE (organization_id, fqdn)
);
CREATE INDEX idx_domains_org ON domains (organization_id);
CREATE INDEX idx_domains_fqdn ON domains (fqdn);

CREATE TABLE hostnames (
    id                     uuid PRIMARY KEY,
    domain_id              uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    application_instance_id uuid,          -- populated by Phase 5 (G5)
    hostname               text NOT NULL,
    status                 text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT hostnames_org_domain_key UNIQUE (domain_id, hostname)
);
CREATE INDEX idx_hostnames_domain ON hostnames (domain_id);

-- Registry of DNS providers configured per organization (spec §85).
CREATE TABLE dns_providers (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    provider        text NOT NULL CHECK (provider IN ('manual', 'cloudflare')),
    name            text NOT NULL,
    config          jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT dns_providers_org_name_key UNIQUE (organization_id, name)
);

-- Append-only log of domain verification attempts.
CREATE TABLE domain_verifications (
    id         uuid PRIMARY KEY,
    domain_id  uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    method     text NOT NULL DEFAULT 'dns_txt',
    success    boolean NOT NULL,
    detail     text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_domain_verifications_domain ON domain_verifications (domain_id);

-- +goose Down
DROP TABLE IF EXISTS domain_verifications;
DROP TABLE IF EXISTS dns_providers;
DROP TABLE IF EXISTS hostnames;
DROP TABLE IF EXISTS domains;