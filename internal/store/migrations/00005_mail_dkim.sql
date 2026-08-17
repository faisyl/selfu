-- 00005_mail_dkim.sql
-- Phase 4b (G4b): DKIM provisioning metadata for mail domains (spec §28, §68).

-- +goose Up
ALTER TABLE mail_domains
    ADD COLUMN dkim_selector text NOT NULL DEFAULT '',
    ADD COLUMN dkim_dns_record text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE mail_domains
    DROP COLUMN IF EXISTS dkim_selector,
    DROP COLUMN IF EXISTS dkim_dns_record;