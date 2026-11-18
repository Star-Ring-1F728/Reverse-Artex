"""Local Go/Python interop fixture. Reads ephemeral test keys only from stdin."""
import base64
import json
import sys
from reverse_artex_guard import Guard, ObjectSnapshot

data = json.load(sys.stdin)
config = data["config"]
for key in ("private_key", "identity_key", "session_key"):
    config[key] = base64.b64decode(config[key])
guard = Guard(**config)
snapshot = ObjectSnapshot(**data["snapshot"])
snapshot = ObjectSnapshot(snapshot.canonical_id, snapshot.tenant, snapshot.owner, tuple(snapshot.grants),
                          snapshot.authz_revision, snapshot.content_revision, snapshot.payload)
rep = guard.read(data["method"], data["target"], data["headers"], lambda _: snapshot)
json.dump({"status": rep.status, "body": base64.b64encode(rep.body).decode(), "headers": dict(rep.headers)}, sys.stdout)
