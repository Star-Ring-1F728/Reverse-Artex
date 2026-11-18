-- M6-3 single-writer PostgreSQL 15+. Apply only after a verified backup.
-- No retention DELETE job or writer credentials are included in this migration.
BEGIN;

CREATE TABLE IF NOT EXISTS ra_schema_migrations (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ra_cases (
    case_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    asset_id text NOT NULL,
    first_alert_at timestamptz NOT NULL,
    last_alert_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'reviewing', 'closed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(case_id) BETWEEN 1 AND 128),
    CHECK (length(tenant_id) BETWEEN 1 AND 128),
    CHECK (length(asset_id) BETWEEN 1 AND 128),
    CHECK (last_alert_at >= first_alert_at),
    UNIQUE (case_id, tenant_id, asset_id)
);

-- event_id is unique only within stream, tenant and asset. The exact JSONL
-- line hash is retained so a retry with changed bytes fails projection.
CREATE TABLE IF NOT EXISTS ra_evidence_records (
    stream text NOT NULL CHECK (stream IN ('events', 'host-events')),
    tenant_id text NOT NULL,
    asset_id text NOT NULL,
    event_id text NOT NULL,
    line_sha256 bytea NOT NULL CHECK (octet_length(line_sha256) = 32),
    event_time timestamptz NOT NULL,
    imported_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (stream, tenant_id, asset_id, event_id)
);

CREATE TABLE IF NOT EXISTS ra_case_evidence (
    case_id text NOT NULL,
    tenant_id text NOT NULL,
    asset_id text NOT NULL,
    stream text NOT NULL,
    event_id text NOT NULL,
    PRIMARY KEY (case_id, stream, event_id),
    FOREIGN KEY (case_id, tenant_id, asset_id)
        REFERENCES ra_cases (case_id, tenant_id, asset_id) ON DELETE RESTRICT,
    FOREIGN KEY (stream, tenant_id, asset_id, event_id)
        REFERENCES ra_evidence_records (stream, tenant_id, asset_id, event_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS ra_case_alerts (
    stream text NOT NULL CHECK (stream IN ('alerts', 'host-alerts')),
    line_sha256 bytea NOT NULL CHECK (octet_length(line_sha256) = 32),
    case_id text NOT NULL,
    tenant_id text NOT NULL,
    asset_id text NOT NULL,
    rule_id text NOT NULL,
    alert_time timestamptz NOT NULL,
    PRIMARY KEY (stream, line_sha256),
    FOREIGN KEY (case_id, tenant_id, asset_id)
        REFERENCES ra_cases (case_id, tenant_id, asset_id) ON DELETE RESTRICT
);

-- A policy may expire or be revoked, but its history row and evidence link stay.
CREATE TABLE IF NOT EXISTS ra_policy_history (
    policy_id text PRIMARY KEY,
    source_case_id text NOT NULL,
    case_id text REFERENCES ra_cases (case_id) ON DELETE RESTRICT,
    tenant_id text NOT NULL,
    asset_id text NOT NULL,
    rule_version text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    last_operation text NOT NULL CHECK (last_operation IN ('issued', 'expired', 'revoked', 'rolled_back')),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '60 seconds')
);

CREATE TABLE IF NOT EXISTS ra_control_audit (
    epoch text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    operation text NOT NULL,
    operation_at timestamptz NOT NULL,
    line_sha256 bytea NOT NULL CHECK (octet_length(line_sha256) = 32),
    policy_id text REFERENCES ra_policy_history (policy_id) ON DELETE RESTRICT,
    PRIMARY KEY (epoch, version)
);

CREATE TABLE IF NOT EXISTS ra_projection_cursors (
    source text PRIMARY KEY,
    segment_number bigint NOT NULL CHECK (segment_number >= 0),
    line_number bigint NOT NULL CHECK (line_number >= 0),
    line_sha256 bytea NOT NULL CHECK (octet_length(line_sha256) = 32),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Initial full projection imports are immutable. Incremental cursors above
-- are reserved for a later segment-aware importer.
CREATE TABLE IF NOT EXISTS ra_projection_imports (
    source_id text PRIMARY KEY,
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    imported_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(source_id) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS ra_audit_imports (
    source_id text PRIMARY KEY,
    wal_sha256 bytea NOT NULL CHECK (octet_length(wal_sha256) = 32),
    row_count bigint NOT NULL CHECK (row_count > 0),
    imported_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(source_id) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS ra_retention_holds (
    hold_id text PRIMARY KEY,
    case_id text NOT NULL REFERENCES ra_cases (case_id) ON DELETE RESTRICT,
    reason text NOT NULL,
    placed_at timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    CHECK (released_at IS NULL OR released_at >= placed_at)
);

-- Only separately provisioned reader roles may view a tenant. The writer
-- must use a distinct trusted DB role; do not grant readers table ownership.
CREATE TABLE IF NOT EXISTS ra_reader_grants (
    role_name name PRIMARY KEY,
    tenant_id text NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128)
);

ALTER TABLE ra_reader_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE ra_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE ra_evidence_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE ra_case_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE ra_case_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ra_policy_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE ra_control_audit ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename='ra_reader_grants' AND policyname='ra_reader_own_grant') THEN
        CREATE POLICY ra_reader_own_grant ON ra_reader_grants FOR SELECT USING (role_name=current_user);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename='ra_cases' AND policyname='ra_reader_cases') THEN
        CREATE POLICY ra_reader_cases ON ra_cases FOR SELECT USING (tenant_id=(SELECT tenant_id FROM ra_reader_grants WHERE role_name=current_user));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename='ra_evidence_records' AND policyname='ra_reader_evidence') THEN
        CREATE POLICY ra_reader_evidence ON ra_evidence_records FOR SELECT USING (tenant_id=(SELECT tenant_id FROM ra_reader_grants WHERE role_name=current_user));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename='ra_case_evidence' AND policyname='ra_reader_links') THEN
        CREATE POLICY ra_reader_links ON ra_case_evidence FOR SELECT USING (tenant_id=(SELECT tenant_id FROM ra_reader_grants WHERE role_name=current_user));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename='ra_case_alerts' AND policyname='ra_reader_alerts') THEN
        CREATE POLICY ra_reader_alerts ON ra_case_alerts FOR SELECT USING (tenant_id=(SELECT tenant_id FROM ra_reader_grants WHERE role_name=current_user));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename='ra_policy_history' AND policyname='ra_reader_policies') THEN
        CREATE POLICY ra_reader_policies ON ra_policy_history FOR SELECT USING (tenant_id=(SELECT tenant_id FROM ra_reader_grants WHERE role_name=current_user));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename='ra_control_audit' AND policyname='ra_reader_audit') THEN
        CREATE POLICY ra_reader_audit ON ra_control_audit FOR SELECT USING (EXISTS (SELECT 1 FROM ra_policy_history p WHERE p.policy_id=ra_control_audit.policy_id));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ra_evidence_time_idx ON ra_evidence_records (event_time);
CREATE INDEX IF NOT EXISTS ra_case_tenant_time_idx ON ra_cases (tenant_id, last_alert_at DESC);
CREATE INDEX IF NOT EXISTS ra_case_evidence_lookup_idx ON ra_case_evidence (stream, tenant_id, asset_id, event_id);
CREATE INDEX IF NOT EXISTS ra_policy_expiry_idx ON ra_policy_history (expires_at);
CREATE INDEX IF NOT EXISTS ra_holds_active_idx ON ra_retention_holds (case_id) WHERE released_at IS NULL;

INSERT INTO ra_schema_migrations (version) VALUES (1) ON CONFLICT (version) DO NOTHING;
COMMIT;
