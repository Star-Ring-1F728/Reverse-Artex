-- B05-D: immutable, explicitly selected policy/audit snapshot per case commit.
-- Apply after 0004 and a verified backup. No roles, grants or legacy backfill.
BEGIN;
SET LOCAL search_path=pg_catalog,public;
CREATE TABLE public.ra_case_policy_bindings (
 tenant_id text NOT NULL,
 case_id text NOT NULL,
 revision integer NOT NULL,
 source_namespace text NOT NULL,
 snapshot_sha256 bytea NOT NULL,
 commit_sha256 bytea NOT NULL CHECK(octet_length(commit_sha256)=32),
 binding_sha256 bytea NOT NULL CHECK(octet_length(binding_sha256)=32),
 audit_keys text[] NOT NULL CHECK(cardinality(audit_keys) BETWEEN 1 AND 128),
 canonical_binding bytea NOT NULL CHECK(octet_length(canonical_binding) BETWEEN 1 AND 262144),
 PRIMARY KEY(tenant_id,case_id,revision),
 FOREIGN KEY(tenant_id,case_id,revision,commit_sha256) REFERENCES public.ra_case_revisions(tenant_id,case_id,revision,commit_sha256) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,case_id,revision,source_namespace,snapshot_sha256) REFERENCES public.ra_case_revisions(tenant_id,case_id,revision,source_namespace,snapshot_sha256) ON DELETE RESTRICT
);
ALTER TABLE public.ra_case_policy_bindings ENABLE ROW LEVEL SECURITY;
CREATE POLICY case_policy_writer_read ON public.ra_case_policy_bindings FOR SELECT USING (
 EXISTS(SELECT 1 FROM public.ra_source_registry r WHERE r.source_namespace=ra_case_policy_bindings.source_namespace AND r.tenant_id=ra_case_policy_bindings.tenant_id AND r.writer_role=current_user AND r.enabled));
CREATE POLICY case_policy_writer_insert ON public.ra_case_policy_bindings FOR INSERT WITH CHECK (
 EXISTS(SELECT 1 FROM public.ra_source_registry r WHERE r.source_namespace=ra_case_policy_bindings.source_namespace AND r.tenant_id=ra_case_policy_bindings.tenant_id AND r.writer_role=current_user AND r.enabled));
CREATE POLICY case_policy_reader ON public.ra_case_policy_bindings FOR SELECT USING (
 tenant_id=(SELECT tenant_id FROM public.ra_reader_grants WHERE role_name=current_user));
CREATE FUNCTION public.ra_case_policy_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'case policy bindings are immutable'; END $$;
CREATE TRIGGER case_policy_immutable BEFORE UPDATE OR DELETE ON public.ra_case_policy_bindings FOR EACH ROW EXECUTE FUNCTION public.ra_case_policy_immutable();
REVOKE ALL ON FUNCTION public.ra_case_policy_immutable() FROM PUBLIC;
REVOKE ALL ON public.ra_case_policy_bindings FROM PUBLIC;

-- Legacy removal rows have NULL policy_id. Permit only audit keys in a visible
-- explicit binding; existing issue-row and tenant policies remain unchanged.
CREATE POLICY case_bound_audit_read ON public.ra_control_audit FOR SELECT USING (
 EXISTS(SELECT 1 FROM public.ra_case_policy_bindings b WHERE
 b.audit_keys @> ARRAY[ra_control_audit.epoch||':'||ra_control_audit.version::text]));
CREATE INDEX ra_case_policy_audit_keys_idx ON public.ra_case_policy_bindings USING gin(audit_keys);
INSERT INTO public.ra_schema_migrations(version) VALUES(5);
COMMIT;
