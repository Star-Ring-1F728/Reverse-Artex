-- B04-B additive source ledger, PostgreSQL 15+. Apply after a verified backup.
-- Requires 0001. No legacy backfill, role provisioning, or runtime activation.
BEGIN;
SET LOCAL search_path=public,pg_catalog;

CREATE TABLE ra_source_registry (
    source_namespace text NOT NULL CHECK (source_namespace ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.:/{}-]{1,128}$'),
    writer_role name NOT NULL,
    metadata_sha256 bytea NOT NULL CHECK (octet_length(metadata_sha256)=32),
    enabled boolean NOT NULL DEFAULT false,
    PRIMARY KEY (source_namespace, tenant_id)
);

CREATE TABLE ra_source_snapshots (
    source_namespace text NOT NULL,
    tenant_id text NOT NULL,
    snapshot_sha256 bytea NOT NULL CHECK (octet_length(snapshot_sha256)=32),
    metadata_sha256 bytea NOT NULL CHECK (octet_length(metadata_sha256)=32),
    plan_sha256 bytea NOT NULL CHECK (octet_length(plan_sha256)=32),
    imported_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_namespace, tenant_id, snapshot_sha256),
    FOREIGN KEY (source_namespace,tenant_id) REFERENCES ra_source_registry ON DELETE RESTRICT
);

CREATE TABLE ra_source_streams (
    source_namespace text NOT NULL,
    tenant_id text NOT NULL,
    snapshot_sha256 bytea NOT NULL,
    stream text NOT NULL CHECK (stream IN ('events','evaluations','alerts','host-events','host-evaluations','host-alerts')),
    record_count integer NOT NULL CHECK (record_count BETWEEN 0 AND 100000),
    stream_sha256 bytea NOT NULL CHECK (octet_length(stream_sha256)=32),
    PRIMARY KEY (source_namespace,tenant_id,snapshot_sha256,stream),
    FOREIGN KEY (source_namespace,tenant_id,snapshot_sha256) REFERENCES ra_source_snapshots ON DELETE RESTRICT
);

CREATE TABLE ra_source_records (
    source_namespace text NOT NULL,
    tenant_id text NOT NULL,
    stream text NOT NULL CHECK (stream IN ('events','host-events')),
    asset_id text NOT NULL CHECK (asset_id ~ '^[A-Za-z0-9_.:/{}-]{1,128}$'),
    sensor_id text NOT NULL CHECK (sensor_id ~ '^[A-Za-z0-9_.:/{}-]{1,128}$'),
    event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9_.:/{}-]{1,128}$'),
    line_sha256 bytea NOT NULL CHECK (octet_length(line_sha256)=32),
    PRIMARY KEY (source_namespace,tenant_id,stream,asset_id,sensor_id,event_id),
    UNIQUE (source_namespace,tenant_id,stream,asset_id,sensor_id,event_id,line_sha256),
    FOREIGN KEY (source_namespace,tenant_id) REFERENCES ra_source_registry ON DELETE RESTRICT
);

CREATE TABLE ra_source_occurrences (
    source_namespace text NOT NULL,
    tenant_id text NOT NULL,
    snapshot_sha256 bytea NOT NULL,
    stream text NOT NULL,
    commit_ordinal integer NOT NULL CHECK (commit_ordinal BETWEEN 1 AND 100000),
    asset_id text NOT NULL,
    sensor_id text NOT NULL,
    event_id text NOT NULL,
    line_sha256 bytea NOT NULL,
    evaluation_sha256 bytea NOT NULL CHECK (octet_length(evaluation_sha256)=32),
    evaluation_result text NOT NULL CHECK (length(evaluation_result) BETWEEN 1 AND 64),
    PRIMARY KEY (source_namespace,tenant_id,snapshot_sha256,stream,commit_ordinal),
    FOREIGN KEY (source_namespace,tenant_id,snapshot_sha256,stream) REFERENCES ra_source_streams ON DELETE RESTRICT,
    FOREIGN KEY (source_namespace,tenant_id,stream,asset_id,sensor_id,event_id,line_sha256)
        REFERENCES ra_source_records (source_namespace,tenant_id,stream,asset_id,sensor_id,event_id,line_sha256) ON DELETE RESTRICT
);

ALTER TABLE ra_source_registry ENABLE ROW LEVEL SECURITY;
CREATE POLICY source_writer_registration ON ra_source_registry FOR SELECT USING (writer_role=current_user);

-- No SECURITY DEFINER helpers and no implicit writer/reader grants. Provision
-- a non-owner writer with SELECT on registry, SELECT+INSERT on the four ledger
-- tables, and SELECT on ra_reader_grants for policy evaluation. Never grant
-- ledger UPDATE/DELETE, registry writes, table ownership or BYPASSRLS.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['ra_source_snapshots','ra_source_streams','ra_source_records','ra_source_occurrences'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
        EXECUTE format('CREATE POLICY source_writer_read ON %I FOR SELECT USING (EXISTS (SELECT 1 FROM ra_source_registry r WHERE r.source_namespace=%I.source_namespace AND r.tenant_id=%I.tenant_id AND r.writer_role=current_user AND r.enabled))',t,t,t);
        EXECUTE format('CREATE POLICY source_writer_insert ON %I FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM ra_source_registry r WHERE r.source_namespace=%I.source_namespace AND r.tenant_id=%I.tenant_id AND r.writer_role=current_user AND r.enabled))',t,t,t);
        EXECUTE format('CREATE POLICY source_tenant_reader ON %I FOR SELECT USING (tenant_id=(SELECT tenant_id FROM ra_reader_grants WHERE role_name=current_user))',t);
    END LOOP;
END $$;

-- Bind snapshot configuration at the DB boundary, including direct SQL inserts.
CREATE POLICY source_snapshot_config ON ra_source_snapshots AS RESTRICTIVE FOR INSERT
WITH CHECK (EXISTS (SELECT 1 FROM ra_source_registry r
    WHERE r.source_namespace=ra_source_snapshots.source_namespace AND r.tenant_id=ra_source_snapshots.tenant_id
    AND r.writer_role=current_user AND r.enabled AND r.metadata_sha256=ra_source_snapshots.metadata_sha256));

CREATE INDEX ra_source_occurrences_record_idx ON ra_source_occurrences
    (source_namespace,tenant_id,stream,asset_id,sensor_id,event_id,line_sha256);

INSERT INTO ra_schema_migrations(version) VALUES (2);
COMMIT;
