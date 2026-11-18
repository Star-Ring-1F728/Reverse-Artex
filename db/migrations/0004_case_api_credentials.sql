-- B04-D: operator-issued opaque credentials; no automatic roles or grants.
-- Apply after 0003 in an explicitly selected DB with a verified backup.
BEGIN;
SET LOCAL search_path=pg_catalog,public;
CREATE TABLE public.ra_case_api_credentials (
 token_sha256 bytea PRIMARY KEY CHECK(octet_length(token_sha256)=32),
 principal_id text NOT NULL CHECK(principal_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
 service_role name NOT NULL,
 reader_role name NOT NULL,
 tenant_id text NOT NULL CHECK(tenant_id ~ '^[A-Za-z0-9_.:/{}-]{1,128}$'),
 not_before timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 CHECK(expires_at>not_before),
 CHECK(isfinite(not_before) AND isfinite(expires_at)),
 CHECK(service_role<>reader_role)
);
ALTER TABLE public.ra_case_api_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY case_api_service_credentials ON public.ra_case_api_credentials
 FOR SELECT USING(service_role=current_user);
REVOKE ALL ON public.ra_case_api_credentials FROM PUBLIC;
-- Service: LOGIN NOINHERIT, SELECT on this table, SET membership of dedicated
-- reader roles only. Readers retain the 0002/0003 SELECT and RLS contract.
-- Operator alone provisions/rotates/disables credentials and reader grants.
INSERT INTO public.ra_schema_migrations(version) VALUES(4);
COMMIT;