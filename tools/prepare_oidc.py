"""Prepare a pinned public OIDC trust snapshot; no private keys or tokens.

Fetches only explicit issuer discovery and its same-origin JWKS once. The
request path in edge/SDK never calls this helper or refreshes keys implicitly.
"""
import argparse
import json
from pathlib import Path
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))
from reverse_artex_guard.oidc import OIDCVerifier, _issuer, _object


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def read_object(path):
    p = Path(path)
    info = p.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
        raise ValueError("bounded regular OIDC input required")
    return _object(p.read_bytes(), 65536)


def prepare(issuer, audience, client_id, subjects, tenant_claim="ra_tenant", max_lifetime=300):
    if not _issuer(issuer):
        raise ValueError("HTTPS issuer or explicit literal-loopback development issuer required")
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def fetch(url):
        req = urllib.request.Request(url, headers={"Accept": "application/json", "Accept-Encoding": "identity"})
        try:
            with http.open(req, timeout=5) as response:
                if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                    raise ValueError("OIDC discovery representation rejected")
                return _object(response.read(65537), 65536)
        except urllib.error.HTTPError as error:
            error.close()
            raise ValueError("OIDC public fetch returned a rejected status") from None
    discovery = fetch(issuer + "/.well-known/openid-configuration")
    uri = discovery.get("jwks_uri")
    source = urllib.parse.urlsplit(issuer)
    target = urllib.parse.urlsplit(uri) if isinstance(uri, str) else None
    if discovery.get("issuer") != issuer or target is None or target.scheme != source.scheme or target.netloc != source.netloc or target.query or target.fragment or not uri.startswith(issuer + "/") or not _issuer(uri):
        raise ValueError("discovery issuer/JWKS scope mismatch")
    public = fetch(uri)
    if not isinstance(public.get("keys"), list) or len(public["keys"]) > 32:
        raise ValueError("bounded public JWKS required")
    keys = []
    for key in public["keys"]:
        if not isinstance(key, dict) or any(field in key for field in ("d", "p", "q", "dp", "dq", "qi", "k")):
            raise ValueError("JWKS contains nonpublic key material")
        if key.get("kty") == "RSA" and key.get("use") == "sig" and key.get("alg") == "RS256":
            keys.append({field: key[field] for field in ("kid", "n", "e")})
    keys.sort(key=lambda k: k["kid"])
    config = {"schema": "oidc-rs256/1", "issuer": issuer, "audience": audience, "client_id": client_id,
              "tenant_claim": tenant_claim, "max_lifetime_seconds": max_lifetime, "subjects": subjects, "keys": keys}
    verifier = OIDCVerifier(config)
    return config, verifier.digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--subjects", required=True, help="operator-owned subject UUID to principal/tenant JSON object")
    parser.add_argument("--tenant-claim", default="ra_tenant")
    parser.add_argument("--max-lifetime-seconds", type=int, default=300)
    parser.add_argument("--out", required=True, help="new public configuration file; never overwrite an active pin")
    args = parser.parse_args()
    try:
        config, digest = prepare(args.issuer, args.audience, args.client_id, read_object(args.subjects), args.tenant_claim, args.max_lifetime_seconds)
        path = Path(args.out)
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(config, handle, ensure_ascii=True, indent=2)
            handle.write("\n")
        path.chmod(0o600)
    except Exception as error:
        print(json.dumps({"passed": False, "error_type": type(error).__name__, "reason": "OIDC public trust snapshot was not accepted"}))
        return 1
    print(json.dumps({"schema": "oidc-config-check/1", "passed": True, "identity_config_sha256": digest,
                      "keys": len(config["keys"]), "subjects": len(config["subjects"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
