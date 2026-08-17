-- 00002_identity.sql
-- Phase 2 (G2): organizations, memberships, groups, group memberships and
-- external-resource tracking (spec §7, §8, §22; tables §85).

-- +goose Up
CREATE TABLE organizations (
    id         uuid PRIMARY KEY,
    name       text NOT NULL,
    slug       text NOT NULL,
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT organizations_slug_key UNIQUE (slug),
    CONSTRAINT organizations_name_key UNIQUE (name)
);

CREATE TABLE organization_memberships (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role            text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT membership_unique UNIQUE (organization_id, user_id)
);

CREATE INDEX idx_memberships_org ON organization_memberships (organization_id);
CREATE INDEX idx_memberships_user ON organization_memberships (user_id);

CREATE TABLE groups (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name            text NOT NULL,
    slug            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT groups_org_slug_key UNIQUE (organization_id, slug)
);

CREATE TABLE group_memberships (
    group_id    uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_group_memberships_user ON group_memberships (user_id);

-- Tracks a platform object's counterpart in an external provider (authentik,
-- later chasquid, traefik, docker) with explicit external ids (spec §16, §22).
CREATE TABLE external_resources (
    id                  uuid PRIMARY KEY,
    resource_type       text NOT NULL,
    platform_object_id  uuid NOT NULL,
    provider            text NOT NULL,
    external_id         text NOT NULL,
    desired_hash        text NOT NULL DEFAULT '',
    observed_hash       text NOT NULL DEFAULT '',
    status              text NOT NULL DEFAULT 'provisioning'
                        CHECK (status IN ('provisioning', 'active', 'failed', 'removed')),
    last_error          text NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT external_resource_type_object UNIQUE (resource_type, platform_object_id)
);

CREATE INDEX idx_external_provider ON external_resources (provider, external_id);

-- +goose Down
DROP TABLE IF EXISTS external_resources;
DROP TABLE IF EXISTS group_memberships;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS organization_memberships;
DROP TABLE IF EXISTS organizations;