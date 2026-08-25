-- 00008_installation.sql
-- Onboarding state (bootstrap wizard): the installation singleton carries the
-- local domain, the associated primary domain, and the configured external
-- access provider (spec §88, G8/G9).

-- +goose Up
CREATE TABLE installation (
    id                boolean PRIMARY KEY DEFAULT TRUE CHECK (id),  -- singleton row
    local_domain      text NOT NULL DEFAULT 'selfu.local',
    primary_domain_id uuid REFERENCES domains (id) ON DELETE SET NULL,
    dns_provider      text NOT NULL DEFAULT 'manual'
                      CHECK (dns_provider IN ('manual', 'cloudflare')),
    access_provider   text NOT NULL DEFAULT 'manual'
                      CHECK (access_provider IN ('manual', 'cloudflare')),
    provider_config   bytea NOT NULL DEFAULT '',   -- encrypted provider credentials
    onboarded_at      timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- The singleton row exists from the first migration run; onboarding flips it.
INSERT INTO installation (id) VALUES (TRUE) ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS installation;
