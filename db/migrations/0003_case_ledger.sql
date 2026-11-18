-- B04-C additive case/source revision ledger. Apply after verified backup.
-- No roles, registry entries, grants, legacy backfill or runtime activation.
BEGIN;
SET LOCAL search_path=public,pg_catalog;
CREATE TABLE ra_case_heads (
 tenant_id text NOT NULL,
 case_id text NOT NULL CHECK(case_id ~ '^[A-Za-z0-9_.:/{}-]{1,128}$'),
 source_namespace text NOT NULL,
 asset_ids text[] NOT NULL CHECK(cardinality(asset_ids) BETWEEN 1 AND 8),
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 64),
 commit_sha256 bytea NOT NULL CHECK(octet_length(commit_sha256)=32),
 PRIMARY KEY(tenant_id,case_id),
 UNIQUE(tenant_id,case_id,source_namespace,asset_ids)
);
CREATE TABLE ra_case_revisions (
 tenant_id text NOT NULL,
 case_id text NOT NULL,
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 64),
 source_namespace text NOT NULL,
 asset_ids text[] NOT NULL,
 snapshot_sha256 bytea NOT NULL,
 commit_sha256 bytea NOT NULL CHECK(octet_length(commit_sha256)=32),
 previous_commit_sha256 bytea NOT NULL CHECK(octet_length(previous_commit_sha256)=CASE WHEN revision=1 THEN 0 ELSE 32 END),
 observed_at text NOT NULL CHECK(observed_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z$'),
 plan_sha256 bytea NOT NULL CHECK(octet_length(plan_sha256)=32),
 canonical_plan bytea NOT NULL CHECK(octet_length(canonical_plan) BETWEEN 1 AND 4194304),
 PRIMARY KEY(tenant_id,case_id,revision),
 UNIQUE(tenant_id,case_id,revision,commit_sha256),
 UNIQUE(tenant_id,case_id,revision,source_namespace,snapshot_sha256),
 FOREIGN KEY(tenant_id,case_id,source_namespace,asset_ids) REFERENCES ra_case_heads(tenant_id,case_id,source_namespace,asset_ids) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(source_namespace,tenant_id,snapshot_sha256) REFERENCES ra_source_snapshots ON DELETE RESTRICT
);
ALTER TABLE ra_case_heads ADD CONSTRAINT ra_case_head_revision_fk FOREIGN KEY(tenant_id,case_id,revision,commit_sha256) REFERENCES ra_case_revisions(tenant_id,case_id,revision,commit_sha256) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE ra_case_refs (
 tenant_id text NOT NULL,
 case_id text NOT NULL,
 revision integer NOT NULL,
 ref_id text NOT NULL CHECK(length(ref_id) BETWEEN 1 AND 128),
 source_namespace text NOT NULL,
 snapshot_sha256 bytea NOT NULL,
 stream text NOT NULL,
 commit_ordinal integer NOT NULL,
 PRIMARY KEY(tenant_id,case_id,revision,ref_id),
 FOREIGN KEY(tenant_id,case_id,revision,source_namespace,snapshot_sha256) REFERENCES ra_case_revisions(tenant_id,case_id,revision,source_namespace,snapshot_sha256) ON DELETE RESTRICT,
 FOREIGN KEY(source_namespace,tenant_id,snapshot_sha256,stream,commit_ordinal) REFERENCES ra_source_occurrences ON DELETE RESTRICT
);

-- Invoker triggers run under writer RLS. No SECURITY DEFINER or elevated helper.
CREATE FUNCTION ra_case_head_transition() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE v public.ra_case_revisions;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 THEN RAISE EXCEPTION 'case head must begin at one'; END IF;
 ELSE
  IF (NEW.tenant_id,NEW.case_id,NEW.source_namespace,NEW.asset_ids) IS DISTINCT FROM (OLD.tenant_id,OLD.case_id,OLD.source_namespace,OLD.asset_ids) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'case scope or sequence violation'; END IF;
 END IF;
 SELECT * INTO STRICT v FROM public.ra_case_revisions WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND revision=NEW.revision;
 IF v.commit_sha256<>NEW.commit_sha256 OR v.source_namespace<>NEW.source_namespace OR v.asset_ids<>NEW.asset_ids THEN RAISE EXCEPTION 'case head revision mismatch'; END IF;
 IF TG_OP='UPDATE' AND v.previous_commit_sha256<>OLD.commit_sha256 THEN RAISE EXCEPTION 'case predecessor mismatch'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER ra_case_head_transition BEFORE INSERT OR UPDATE ON ra_case_heads FOR EACH ROW EXECUTE FUNCTION ra_case_head_transition();

-- Reject unpublished extra revisions, gaps, rollback and changed DB parents at
-- commit. Deferred checks permit the initial revision/head cycle and restores.
CREATE FUNCTION ra_case_prefix_check() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE h public.ra_case_heads; n integer; lo integer; hi integer; bad boolean;
BEGIN
 SELECT * INTO STRICT h FROM public.ra_case_heads WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id;
 SELECT count(*),min(revision),max(revision) INTO n,lo,hi FROM public.ra_case_revisions WHERE tenant_id=h.tenant_id AND case_id=h.case_id;
 IF n<>h.revision OR lo<>1 OR hi<>h.revision THEN RAISE EXCEPTION 'case revision prefix/head mismatch'; END IF;
 SELECT EXISTS(SELECT 1 FROM public.ra_case_revisions v LEFT JOIN public.ra_case_revisions p ON p.tenant_id=v.tenant_id AND p.case_id=v.case_id AND p.revision=v.revision-1 WHERE v.tenant_id=h.tenant_id AND v.case_id=h.case_id AND (v.source_namespace<>h.source_namespace OR v.asset_ids<>h.asset_ids OR (v.revision>1 AND (p.revision IS NULL OR v.previous_commit_sha256<>p.commit_sha256 OR v.observed_at<p.observed_at)) OR (v.revision=h.revision AND v.commit_sha256<>h.commit_sha256))) INTO bad;
 IF bad THEN RAISE EXCEPTION 'case revision chain mismatch'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER ra_case_revision_prefix AFTER INSERT ON ra_case_revisions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ra_case_prefix_check();
CREATE CONSTRAINT TRIGGER ra_case_head_prefix AFTER INSERT OR UPDATE ON ra_case_heads DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ra_case_prefix_check();

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['ra_case_heads','ra_case_revisions','ra_case_refs'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY case_writer_read ON %I FOR SELECT USING (EXISTS (SELECT 1 FROM public.ra_source_registry r WHERE r.source_namespace=%I.source_namespace AND r.tenant_id=%I.tenant_id AND r.writer_role=current_user AND r.enabled))',t,t,t);
  EXECUTE format('CREATE POLICY case_writer_insert ON %I FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.ra_source_registry r WHERE r.source_namespace=%I.source_namespace AND r.tenant_id=%I.tenant_id AND r.writer_role=current_user AND r.enabled))',t,t,t);
  EXECUTE format('CREATE POLICY case_tenant_reader ON %I FOR SELECT USING (tenant_id=(SELECT tenant_id FROM public.ra_reader_grants WHERE role_name=current_user))',t);
 END LOOP;
END $$;
CREATE POLICY case_writer_head_update ON ra_case_heads FOR UPDATE USING (EXISTS(SELECT 1 FROM public.ra_source_registry r WHERE r.source_namespace=ra_case_heads.source_namespace AND r.tenant_id=ra_case_heads.tenant_id AND r.writer_role=current_user AND r.enabled)) WITH CHECK(EXISTS(SELECT 1 FROM public.ra_source_registry r WHERE r.source_namespace=ra_case_heads.source_namespace AND r.tenant_id=ra_case_heads.tenant_id AND r.writer_role=current_user AND r.enabled));
-- Provision writers: SELECT+INSERT on these three tables; UPDATE(revision,
-- commit_sha256) on heads only. Readers: SELECT on these and source tables.
-- Both need SELECT on source registry and ra_reader_grants for RLS evaluation.
REVOKE ALL ON FUNCTION ra_case_head_transition(),ra_case_prefix_check() FROM PUBLIC;
INSERT INTO ra_schema_migrations(version) VALUES(3);
COMMIT;
