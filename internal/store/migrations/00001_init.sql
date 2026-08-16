-- 00001_init.sql
-- Phase 1 foundation: platform users and audit events.
-- Email addresses are stored lowercase (CHECK below); identity linkage uses
-- (auth_provider, auth_identity_id), never display names (spec §16).

CREATE TABLE users (
    id               uuid PRIMARY KEY,
    email            text NOT NULL,
    display_name     text NOT NULL DEFAULT '',
    status           text NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active', 'disabled')),
    is_admin         boolean NOT NULL DEFAULT false,
    auth_provider    text NOT NULL,
    auth_identity_id text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    CHECK (email = lower(email)),
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_identity_key UNIQUE (auth_provider, auth_identity_id)
);

CREATE INDEX idx_users_email ON users (email);

CREATE TABLE audit_events (
    id            uuid PRIMARY KEY,
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    actor_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    action        text NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
    resource_type text NOT NULL DEFAULT '',
    resource_id   text NOT NULL DEFAULT '',
    details       jsonb NOT NULL DEFAULT '{}'::jsonb,
    request_id    text NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_events_occurred_at ON audit_events (occurred_at DESC);
CREATE INDEX idx_audit_events_actor ON audit_events (actor_user_id);
CREATE INDEX idx_audit_events_resource ON audit_events (resource_type, resource_id);