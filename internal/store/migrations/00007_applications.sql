-- 00007_applications.sql
-- Phase 5 (G5): application catalog, instances, hostnames and access
-- (spec §13, §20, §17, tables §85).

-- +goose Up
CREATE TABLE catalog_applications (
    id          uuid PRIMARY KEY,
    name        text NOT NULL,
    slug        text NOT NULL,
    version     text NOT NULL,
    description text NOT NULL DEFAULT '',
    category    text NOT NULL DEFAULT '',
    manifest    jsonb NOT NULL,          -- validated catalog manifest
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT catalog_slug_version_key UNIQUE (slug, version)
);

CREATE TABLE application_instances (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    catalog_id      uuid NOT NULL REFERENCES catalog_applications (id),
    name            text NOT NULL,
    slug            text NOT NULL,
    status          text NOT NULL DEFAULT 'provisioning'
                    CHECK (status IN ('provisioning', 'active', 'error', 'removed')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_instances_org ON application_instances (organization_id);

CREATE TABLE application_hostnames (
    id              uuid PRIMARY KEY,
    application_instance_id uuid NOT NULL REFERENCES application_instances (id) ON DELETE CASCADE,
    hostname        text NOT NULL,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT app_hostname_key UNIQUE (hostname)
);
CREATE INDEX idx_app_hostnames_instance ON application_hostnames (application_instance_id);

-- Which platform groups may access an instance (spec §17).
CREATE TABLE application_access_groups (
    application_instance_id uuid NOT NULL REFERENCES application_instances (id) ON DELETE CASCADE,
    group_id                uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (application_instance_id, group_id)
);

-- +goose Down
DROP TABLE IF EXISTS application_access_groups;
DROP TABLE IF EXISTS application_hostnames;
DROP TABLE IF EXISTS application_instances;
DROP TABLE IF EXISTS catalog_applications;