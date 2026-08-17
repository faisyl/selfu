-- 00006_mail_group_aliases.sql
-- Phase 4b (G4b): group-driven aliases (spec §42–43) — an alias may be
-- bound to a platform group; its destinations are the active mail
-- identities of the group's members, reconciled on membership changes.

-- +goose Up
ALTER TABLE mail_aliases
    ADD COLUMN group_id uuid REFERENCES groups (id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE mail_aliases DROP COLUMN IF EXISTS group_id;