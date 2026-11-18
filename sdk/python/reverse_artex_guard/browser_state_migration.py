"""Explicit, bounded in-place browser-state epoch transitions.

No listener, discovery or filesystem copy. A native BEGIN IMMEDIATE serializes
all workers while records, HMAC indexes, metadata, journal and app revocations
commit together. Prepare keyrings before rotation and retire old keys after it.
"""
import hashlib
import hmac
import math
import secrets

from .browser_sso import Unavailable
from .oidc import OIDCVerifier, _ID
from .sqlite_application import SQLiteApplicationStore, _active_session, _revoke_sessions, _DIGEST
from .sqlite_browser_state import (SQLiteBrowserState, PROFILE, _KINDS, _MAX_PLAIN,
                                   _MAX_OPERATIONS, _EPOCH_CHECK, _ZERO, _raw,
                                   _context, _derive, _epoch, _key_id, _keyring,
                                   _journal, _journal_mac, _ms)


def _receipt(item, replayed=False):
    return {k: v for k, v in item.items() if k not in ('mac', 'record_hash', 'previous_hash')} | {'replayed': replayed}


def transition_browser_state(application, source_keys, *, identity_config, public_origin,
                             target_key, expected_epoch, operation_id, capacity=1024,
                             target_identity_config=None, target_public_origin=None,
                             target_capacity=None, session_policy='preserve', mode='rotate',
                             minimum_generation=0):
    """Rotate a key or migrate a trust/capacity context in the SAME native DB.

    `preserve` is valid only for the identical identity pin and public origin.
    A changed pin/origin requires `revoke`: browser-owned native sessions and
    pending login/logout transactions are removed. Same issuer/client logout
    tombstones and jti replay history survive; a new namespace discards them.
    Exact retry of the latest committed operation returns its authenticated
    receipt. Stale epochs, reused operation IDs and retired keys are rejected.
    """
    if type(application) is not SQLiteApplicationStore:
        raise ValueError('native SQLite application lifecycle required')
    if type(source_keys) not in (tuple, list) or not source_keys:
        raise ValueError('source browser state keys required')
    keys = _keyring(source_keys[0], source_keys[1:])
    target_key_id = _key_id(target_key)
    if not isinstance(operation_id, str) or not _ID.fullmatch(operation_id):
        raise ValueError('operation id must be an application identifier of at most 64 characters')
    if not isinstance(expected_epoch, str) or not _DIGEST.fullmatch(expected_epoch):
        raise ValueError('expected browser state epoch required')
    if mode not in ('rotate', 'migrate') or session_policy not in ('preserve', 'revoke'):
        raise ValueError('explicit browser state transition mode and session policy required')
    source_identity = OIDCVerifier(identity_config)
    target_identity = OIDCVerifier(identity_config if target_identity_config is None else target_identity_config)
    target_origin = public_origin if target_public_origin is None else target_public_origin
    target_capacity = capacity if target_capacity is None else target_capacity
    source_context = _context(source_identity.digest, public_origin, capacity)
    target_context = _context(target_identity.digest, target_origin, target_capacity)
    trust_changed = (source_identity.digest, public_origin) != (target_identity.digest, target_origin)
    if trust_changed and session_policy != 'revoke':
        raise ValueError('identity or public origin migration requires explicit session revocation')
    if mode == 'rotate' and source_context != target_context:
        raise ValueError('key rotation requires the exact context; use explicit migration to change it')
    same_namespace = all(source_identity._config[k] == target_identity._config[k] for k in ('issuer', 'client_id'))
    ledger_policy = 'preserve' if same_namespace else 'discard-new-namespace'
    request_hash = hashlib.sha256(_raw(dict(mode=mode, operation_id=operation_id, expected_epoch=expected_epoch,
                                           source_context=source_context, target_context=target_context,
                                           target_key_id=target_key_id, session_policy=session_policy,
                                           ledger_policy=ledger_policy))).hexdigest()
    source_options = dict(identity_digest=source_identity.digest, public_origin=public_origin,
                          capacity=capacity, additional_keys=keys[1:], minimum_generation=minimum_generation)
    target_options = dict(identity_digest=target_identity.digest, public_origin=target_origin,
                          capacity=target_capacity, minimum_generation=minimum_generation)
    with application._write() as db:
        history = _journal(db)
        duplicate = next((item for item in history if item['operation_id'] == operation_id), None)
        if duplicate is not None:
            current = SQLiteBrowserState._in_transaction(application, target_key, db, **target_options)
            if duplicate != history[-1] or not hmac.compare_digest(duplicate['request_hash'], request_hash) or current.epoch != duplicate['to_epoch']:
                raise ValueError('operation id already committed with different parameters or superseded')
            return _receipt(duplicate, True)
        source = SQLiteBrowserState._in_transaction(application, keys[0], db, **source_options)
        if not hmac.compare_digest(source.epoch, expected_epoch):
            raise ValueError('stale browser state epoch')
        if source.generation >= _MAX_OPERATIONS:
            raise ValueError('browser state operation history exhausted')
        if target_key_id == source.key_id:
            if mode == 'rotate' or source_context == target_context:
                raise ValueError('key rotation requires a distinct new key; migration requires a changed context')
        elif target_key_id in {item[k] for item in history for k in ('source_key_id', 'target_key_id')}:
            raise ValueError('retired browser state key cannot be reactivated')
        rows = db.execute('SELECT kind,record_key,expires_ms,digest,nonce,CASE WHEN length(cipher)<=? THEN cipher END '
                          'FROM ra_browser_records ORDER BY kind,record_key LIMIT ?',
                          (_MAX_PLAIN + 16, capacity * 6 + 1)).fetchall()
        counts = {kind: 0 for kind in _KINDS}
        decoded = {kind: [] for kind in _KINDS}
        for kind, *row in rows:
            if kind not in counts:
                raise Unavailable()
            counts[kind] += 1
            if counts[kind] > source._limit(kind):
                raise Unavailable()
            decoded[kind].append(source._open(kind, *row))
        now = application._clock()
        _ms(now)
        cutoff = math.floor(now * 1000)
        # Authenticate EVERY row before pruning. Corruption cannot be hidden by
        # expiry, policy revocation or switching to a new namespace.
        retained = {kind: [(k, v) for k, v in decoded[kind]
                           if source._value(kind, v)[0] > cutoff] for kind in _KINDS}
        revocations = dict(retained['revocation'])
        def blocked(value):
            for k in ((value['sub'], value['sid']), (value['sub'], None), (None, value['sid'])):
                marker = revocations.get(k)
                if marker is not None and (k[1] is not None or value['iat'] <= marker['iat']):
                    return True
            return False
        live = []
        revoke = {v['digest'] for _, v in decoded['session']}
        if session_policy == 'preserve':
            for k, value in retained['session']:
                if not blocked(value) and _active_session(db, value['digest'], value['principal'], value['tenant'], now):
                    live.append((k, value))
                    revoke.discard(value['digest'])
        else:
            retained['transaction'] = []
        retained['session'] = live
        if not same_namespace:
            retained['revocation'], retained['seen'] = [], []
        for kind in _KINDS:
            limit = target_capacity * (2 if kind in ('revocation', 'seen') else 1)
            if len(retained[kind]) > limit:
                raise ValueError('target capacity would discard live browser state')
        used_epochs = {source.epoch} | {item[k] for item in history for k in ('from_epoch', 'to_epoch')}
        for _ in range(8):
            salt = secrets.token_bytes(32)
            next_epoch = _epoch(target_context, target_capacity, salt)
            if salt != source.salt and next_epoch not in used_epochs:
                break
        else:
            raise Unavailable()
        generation = source.generation + 1
        result = dict(profile=PROFILE, source_counts=counts,
                      retained_counts={k: len(retained[k]) for k in _KINDS},
                      dropped_counts={k: counts[k] - len(retained[k]) for k in _KINDS},
                      session_digests_revoked=len(revoke), session_policy=session_policy,
                      ledger_policy=ledger_policy, context=target_context, capacity=target_capacity,
                      created_ms=cutoff)
        document = dict(generation=generation, previous_hash=history[-1]['record_hash'] if history else _ZERO,
                        operation_id=operation_id, request_hash=request_hash, from_epoch=source.epoch,
                        to_epoch=next_epoch, source_key_id=source.key_id, target_key_id=target_key_id,
                        result=result)
        raw_document = _raw(document)
        if len(raw_document) > 4096:
            raise ValueError('browser state operation receipt limit')
        record_hash = hashlib.sha256(raw_document).hexdigest()
        target = SQLiteBrowserState.__new__(SQLiteBrowserState)
        target._setup(application, target_key, target_identity.digest, target_origin, target_capacity,
                      minimum_generation=minimum_generation)
        target.salt = salt
        target.crypto, target.index_key = _derive(target_key, salt)
        target.check_nonce = secrets.token_bytes(12)
        plain = _EPOCH_CHECK + _raw(dict(generation=generation, operation_hash=record_hash, key_id=target_key_id))
        check = target.check_nonce + target.crypto.encrypt(target.check_nonce, plain,
                                                         _raw([PROFILE, target_context, 'meta', salt.hex()]))
        _revoke_sessions(db, sorted(revoke))
        db.execute('DELETE FROM ra_browser_records')
        if db.execute('UPDATE ra_browser_state_meta SET context=?,capacity=?,salt=?,key_check=?,encryptions=1 WHERE id=1',
                      (target_context, target_capacity, salt, check)).rowcount != 1:
            raise Unavailable()
        for kind in _KINDS:
            for key, value in retained[kind]:
                target._store(db, kind, key, value)
        db.execute('CREATE TABLE IF NOT EXISTS ra_browser_state_operations ('
                   'generation INTEGER PRIMARY KEY CHECK(generation BETWEEN 1 AND 128),'
                   'operation_id TEXT NOT NULL UNIQUE,document TEXT NOT NULL CHECK(length(document)<=4096),'
                   'record_hash TEXT NOT NULL CHECK(length(record_hash)=64),mac TEXT NOT NULL CHECK(length(mac)=64))')
        mac = _journal_mac(target.index_key, record_hash)
        db.execute('INSERT INTO ra_browser_state_operations VALUES(?,?,?,?,?)',
                   (generation, operation_id, raw_document.decode('ascii'), record_hash, mac))
        target._adopt(db, target._metadata(db))
        return _receipt(dict(document, record_hash=record_hash, mac=mac))
