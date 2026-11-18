import base64
from contextlib import closing
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from reverse_artex_guard.browser_sso import BrowserSSO, BrowserSSOHandler, NoRedirect, Unavailable
from reverse_artex_guard.browser_tokens import LOGOUT_EVENT, half_hash
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples'))
from sqlite_browser_sessions import SQLiteBrowserSessions


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


class BrowserSSOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.now = int(time.time())
        numbers = self.key.public_key().public_numbers()
        self.config = {'schema': 'oidc-rs256/1', 'issuer': 'http://127.0.0.1:18271/realms/test',
                       'audience': 'reverse-artex', 'client_id': 'browser', 'tenant_claim': 'ra_tenant',
                       'max_lifetime_seconds': 300, 'subjects': {'subject-alice': {'principal': 'alice', 'tenant': 'alpha'},
                                                               'subject-bob': {'principal': 'bob', 'tenant': 'beta'}},
                       'keys': [{'kid': 'key1', 'n': b64(numbers.n.to_bytes(256)), 'e': b64(numbers.e.to_bytes(3))}]}
        self.temp = tempfile.TemporaryDirectory(prefix='ra-browser-unit-')
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'app.db'
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE sessions(digest TEXT PRIMARY KEY,principal TEXT,tenant TEXT,expires REAL)')
        self.backend = SQLiteBrowserSessions(self.db)
        self.sso = BrowserSSO(self.config, public_origin='http://127.0.0.1:18272', lifecycle=self.backend, clock=lambda: self.now)
        self.exchange_calls = 0
        self.servers = []
        self.addCleanup(self.shutdown)

    def shutdown(self):
        for server, thread in self.servers:
            server.shutdown(); server.server_close(); thread.join(2)

    def sign(self, claims, headers=None):
        return jwt.encode(claims, self.key, algorithm='RS256', headers={'kid': 'key1', **(headers or {})})

    def tokens(self, nonce, *, sub='subject-alice', sid='session-one', access_changes=None, identity_changes=None):
        ac = {'iss': self.config['issuer'], 'aud': 'reverse-artex', 'azp': 'browser', 'typ': 'Bearer',
              'sub': sub, 'ra_tenant': 'alpha' if sub == 'subject-alice' else 'beta', 'jti': 'onrtac:' + str(time.monotonic_ns()),
              'sid': sid, 'iat': self.now, 'exp': self.now + 120}
        ac.update(access_changes or {})
        access = self.sign(ac)
        identity = {'iss': self.config['issuer'], 'aud': 'browser', 'azp': 'browser', 'typ': 'ID', 'sub': sub,
                    'sid': sid, 'iat': self.now, 'exp': self.now + 120, 'nonce': nonce, 'at_hash': half_hash(access)}
        identity.update(identity_changes or {})
        return access, self.sign(identity)

    def begin(self):
        response = self.sso.login()
        query = dict(urllib.parse.parse_qsl(dict(response.headers)['Location'].split('?', 1)[1]))
        cookie = next(v for k, v in response.headers if k == 'Set-Cookie').split(';')[0].split('=', 1)[1]
        return query, cookie

    def complete(self, *, sub='subject-alice', sid='session-one', access_changes=None, identity_changes=None, previous=''):
        query, cookie = self.begin()
        def exchange(code, verifier):
            self.exchange_calls += 1
            self.assertEqual(query['code_challenge'], b64(hashlib.sha256(verifier.encode()).digest()))
            self.assertEqual(query['code_challenge_method'], 'S256')
            return self.tokens(query['nonce'], sub=sub, sid=sid, access_changes=access_changes, identity_changes=identity_changes)
        self.sso.exchange = exchange
        response = self.sso.callback({'code': 'code-one', 'state': query['state'], 'iss': self.config['issuer']}, cookie, previous)
        session_cookie = next(v for k, v in response.headers if k == 'Set-Cookie' and v.startswith(self.sso.cookie_name + '='))
        key = session_cookie.split(';')[0].split('=', 1)[1]
        return key, response

    def count(self):
        with closing(sqlite3.connect(self.db)) as db:
            return db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]

    def logout_token(self, *, sub='subject-alice', sid='session-one', changes=None, headers=None):
        claims = {'iss': self.config['issuer'], 'aud': 'browser', 'typ': 'Logout', 'sub': sub, 'sid': sid,
                  'iat': self.now, 'jti': 'logout-' + str(time.monotonic_ns()), 'events': {LOGOUT_EVENT: {}}}
        if sub is None: del claims['sub']
        if sid is None: del claims['sid']
        claims.update(changes or {})
        return self.sign(claims, headers)

    def test_pkce_nonce_bound_identity_installs_only_digest_and_rotates_cookie(self):
        key, response = self.complete()
        s = self.sso.session(key)
        self.assertEqual((s['principal'], s['tenant']), ('alice', 'alpha'))
        self.assertEqual(self.count(), 1)
        with closing(sqlite3.connect(self.db)) as db:
            row = db.execute('SELECT * FROM sessions').fetchone()
        self.assertEqual(row[0], hashlib.sha256(s['access'].encode()).hexdigest())
        self.assertNotIn(s['access'], repr(row))
        cookie = next(v for k, v in response.headers if k == 'Set-Cookie')
        self.assertIn('HttpOnly; SameSite=Lax', cookie)
        new_key, _ = self.complete(previous=key)
        self.assertNotEqual(key, new_key)
        self.assertIsNone(self.sso.session(key))
        self.assertEqual(self.count(), 1)

    def test_callback_rejects_state_cookie_issuer_duplicates_and_replay_before_exchange(self):
        query, cookie = self.begin()
        self.sso.exchange = lambda *_: self.fail('state rejection reached token endpoint')
        for state, binding in ((query['state'], ''), (query['state'], 'x' * 43), ('x' * 43, cookie)):
            with self.assertRaises(ValueError): self.sso.callback({'state': state, 'code': 'c'}, binding)
        with self.assertRaises(ValueError): BrowserSSOHandler._query('code=a&code=b&state=x')
        with self.assertRaises(ValueError): self.sso.callback({'state': query['state'], 'code': 'c', 'iss': 'https://wrong.invalid'}, cookie)
        with self.assertRaises(ValueError): self.sso.callback({'state': query['state'], 'code': 'c'}, cookie)
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.sso.cookie('ra_browser_dev=' + 'a' * 43 + '; ra_browser_dev=' + 'b' * 43), '')

    def test_failed_exchange_consumes_transaction(self):
        query, cookie = self.begin()
        def unavailable(*_): raise Unavailable()
        self.sso.exchange = unavailable
        with self.assertRaises(Unavailable): self.sso.callback({'state': query['state'], 'code': 'c'}, cookie)
        with self.assertRaises(ValueError): self.sso.callback({'state': query['state'], 'code': 'c'}, cookie)
        self.assertEqual(self.count(), 0)

    def test_identity_token_cannot_replace_access_or_cross_subject_session_nonce_hash(self):
        changes = [{'nonce': 'wrong'}, {'sid': 'other'}, {'sub': 'subject-bob'}, {'aud': 'reverse-artex'},
                   {'azp': 'other'}, {'at_hash': 'wrong'}, {'c_hash': 'wrong'}, {'typ': 'Bearer'}, {'exp': self.now},
                   {'iat': self.now + 6}, {'iat': self.now - 10}, {'exp': self.now + 301}]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(ValueError): self.complete(identity_changes=changed)
        with self.assertRaises(ValueError): self.complete(access_changes={'ra_tenant': 'beta'})
        access, identity = self.tokens('n')
        with self.assertRaises(ValueError): self.sso.tokens.login(identity, access, 'n', 'c', self.now, self.now)
        self.assertEqual(self.count(), 0)

    def test_logout_revokes_app_before_posting_provider_hint_and_consumes_return_state(self):
        key, _ = self.complete()
        s = self.sso.session(key)
        with self.assertRaises(ValueError): self.sso.logout(key, 'wrong')
        self.assertEqual(self.count(), 1)
        response = self.sso.logout(key, s['csrf'])
        self.assertIsNone(self.sso.session(key))
        self.assertEqual(self.count(), 0)
        self.assertNotIn('Location', dict(response.headers))
        self.assertIn(b'method="post"', response.body)
        self.assertIn(b'name="id_token_hint"', response.body)
        policy = dict(response.headers)['Content-Security-Policy']
        self.assertIn('form-action http://127.0.0.1:18271 ' + self.sso.public_origin + ';', policy)
        self.assertNotIn(s['access'].encode(), response.body)
        state = next(state for state, tx in self.sso.transactions.items() if tx['kind'] == 'logout')
        tx = self.sso.transactions[state]
        with self.assertRaises(ValueError): self.sso.logged_out({'state': state}, 'wrong')
        self.assertEqual(self.sso.logged_out({'state': state}, tx['binding']).status, 303)
        with self.assertRaises(ValueError): self.sso.logged_out({'state': state}, tx['binding'])

    def test_backchannel_removes_only_matching_sid_and_rejects_replay(self):
        first, _ = self.complete()
        second, _ = self.complete(sid='session-two')
        bob, _ = self.complete(sub='subject-bob', sid='session-three')
        token = self.logout_token()
        self.assertEqual(self.sso.backchannel(token).status, 200)
        self.assertIsNone(self.sso.session(first))
        self.assertIsNotNone(self.sso.session(second))
        self.assertIsNotNone(self.sso.session(bob))
        self.assertEqual(self.count(), 2)
        with self.assertRaises(ValueError): self.sso.backchannel(token)
        with self.assertRaises(ValueError): self.complete()
        self.sso.backchannel(self.logout_token(sid=None))
        self.assertIsNone(self.sso.session(second))
        self.assertIsNotNone(self.sso.session(bob))

    def test_invalid_logout_tokens_never_revoke_sessions(self):
        key, _ = self.complete()
        variants = [{'events': {}}, {'nonce': 'forbidden'}, {'iat': self.now - 61}, {'iat': self.now + 6},
                    {'iss': 'https://other.invalid'}, {'aud': 'reverse-artex'}, {'typ': 'Bearer'}, {'jti': ''},
                    {'exp': self.now}, {'exp': self.now + 601}, {'nbf': self.now + 1}]
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError): self.sso.backchannel(self.logout_token(changes=changed))
        for token in (self.logout_token(sub=None, sid=None), self.logout_token(sub='unknown'), self.logout_token(headers={'jku': 'https://bad.invalid'})):
            with self.assertRaises(ValueError): self.sso.backchannel(token)
        self.assertIsNotNone(self.sso.session(key))
        self.assertEqual(self.count(), 1)

    def test_backchannel_wins_race_against_inflight_callback(self):
        query, cookie = self.begin()
        access, identity = self.tokens(query['nonce'])
        def exchange(*_):
            self.sso.backchannel(self.logout_token())
            return access, identity
        self.sso.exchange = exchange
        with self.assertRaises(ValueError): self.sso.callback({'state': query['state'], 'code': 'c'}, cookie)
        self.assertEqual(self.count(), 0)

    def test_db_revocation_expiry_and_restart_invalidate_browser_session(self):
        key, _ = self.complete()
        self.backend.revoke([self.sso.session(key)['digest']])
        self.assertIsNone(self.sso.session(key))
        key, _ = self.complete()
        other = BrowserSSO(self.config, public_origin=self.sso.public_origin, lifecycle=self.backend)
        self.assertIsNone(other.session(key))
        self.now += 121
        self.assertIsNone(self.sso.session(key))
        self.assertEqual(self.count(), 0)

    def test_db_failures_never_claim_success_or_issue_cookie(self):
        original = self.backend.create
        self.backend.create = lambda *_: (_ for _ in ()).throw(sqlite3.OperationalError())
        with self.assertRaises(sqlite3.OperationalError): self.complete()
        self.assertEqual(len(self.sso.sessions), 0)
        self.backend.create = original
        key, _ = self.complete()
        original = self.backend.revoke
        self.backend.revoke = lambda *_: (_ for _ in ()).throw(sqlite3.OperationalError())
        with self.assertRaises(sqlite3.OperationalError): self.sso.logout(key, self.sso.session(key)['csrf'])
        with self.assertRaises(sqlite3.OperationalError): self.sso.backchannel(self.logout_token())
        self.assertEqual(self.count(), 1)
        self.backend.revoke = original
        self.assertIsNotNone(self.sso.session(key))

    def test_capacity_ttl_and_secure_cookie_configuration(self):
        self.sso.capacity = 1
        query, cookie = self.begin()
        with self.assertRaises(Unavailable): self.begin()
        self.now += 301
        with self.assertRaises(ValueError): self.sso.callback({'state': query['state'], 'code': 'c'}, cookie)
        self.begin()
        secure = BrowserSSO(self.config, public_origin='https://app.example', lifecycle=self.backend)
        self.assertIn('__Host-ra_transaction=', secure.login().headers[1][1])
        self.assertIn('; Secure', secure.login().headers[1][1])
        for url in ('http://example.com', 'https://app.example/path', 'https://app.example/', 'https://app.example?x=1'):
            with self.assertRaises(ValueError): BrowserSSO(self.config, public_origin=url, lifecycle=self.backend)

    def mount(self, handler=BrowserSSOHandler):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        origin = 'http://127.0.0.1:' + str(server.server_port)
        server.sso, server.allow_read, server.edge_origin = self.sso, lambda path: path == '/api/objects/1', origin
        self.sso.public_origin, self.sso.authority = origin, origin.split('://')[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append((server, thread))
        return origin

    def http(self, origin, method, path, data=None, headers=None):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        req = urllib.request.Request(origin + path, data=data, method=method, headers=headers or {})
        try: response = opener.open(req, timeout=3)
        except urllib.error.HTTPError as error: response = error
        with response: return response.status, response.read(), response.headers

    def test_http_origin_csrf_host_method_and_token_storage_boundaries(self):
        origin = self.mount()
        self.assertEqual(self.http(origin, 'GET', '/api/objects/1')[0], 401)
        self.assertEqual(self.http(origin, 'GET', '/')[2]['Referrer-Policy'], 'same-origin')
        key, _ = self.complete()
        cookie = self.sso.cookie_name + '=' + key
        status, body, headers = self.http(origin, 'GET', '/auth/session', headers={'Cookie': cookie})
        session = json.loads(body)
        self.assertTrue(session['authenticated'])
        for field in ('access', 'identity', 'digest', 'sid', 'sub'): self.assertNotIn(field, session)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        for method, path, extra, want in [('GET', '/auth/logout', {}, 405), ('POST', '/auth/logout', {}, 403),
                                         ('POST', '/auth/logout', {'Origin': 'https://evil.invalid'}, 403),
                                         ('GET', '/auth/session', {'Host': 'evil.invalid'}, 400),
                                         ('GET', '/auth/session', {'Authorization': 'Bearer external'}, 400),
                                         ('GET', '/auth/session', {'X-RA-Nonce': 'injected'}, 400),
                                         ('POST', '/api/objects/1', {'Origin': origin}, 405), ('GET', '/private', {}, 404)]:
            with self.subTest(method=method, path=path, extra=extra):
                self.assertEqual(self.http(origin, method, path, headers={'Cookie': cookie, **extra})[0], want)
        data = urllib.parse.urlencode({'csrf': session['csrf']}).encode()
        self.assertEqual(self.http(origin, 'POST', '/auth/logout', data, {'Cookie': cookie, 'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'})[0], 200)
        self.assertEqual(self.count(), 0)
        self.assertFalse(json.loads(self.http(origin, 'GET', '/auth/session', headers={'Cookie': cookie})[1])['authenticated'])

    def test_real_http_exchange_has_pkce_and_rejects_redirect_without_following(self):
        owner = self
        class Provider(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers['Content-Length'])).decode()))
                owner.assertEqual(form['grant_type'], 'authorization_code')
                owner.assertEqual(form['client_id'], 'browser')
                owner.assertEqual(form['code_verifier'], 'v' * 43)
                owner.assertEqual(form['redirect_uri'], owner.sso.public_origin + '/auth/callback')
                self.send_response(302)
                self.send_header('Location', 'http://127.0.0.1:1/not-followed')
                self.end_headers()
        server = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.servers.append((server, thread))
        self.sso.issuer = 'http://127.0.0.1:' + str(server.server_port)
        with self.assertRaises(ValueError): self.sso.exchange('code', 'v' * 43)

    def test_proxy_forwards_server_token_only_and_preserves_acl_status(self):
        key, _ = self.complete()
        access = self.sso.session(key)['access']
        owner = self
        class Edge(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                owner.assertEqual(self.headers['Authorization'], 'Bearer ' + access)
                for field in ('Cookie', 'X-Forwarded-Host', 'Origin', 'X-RA-Nonce'): owner.assertIsNone(self.headers[field])
                self.send_response(403); self.send_header('Content-Type', 'application/json')
                self.send_header('Set-Cookie', 'must-not-forward=1'); self.end_headers(); self.wfile.write(b'{"error":"denied"}')
        edge = ThreadingHTTPServer(('127.0.0.1', 0), Edge)
        thread = threading.Thread(target=edge.serve_forever, daemon=True); thread.start(); self.servers.append((edge, thread))
        origin = self.mount()
        self.servers[-1][0].edge_origin = 'http://127.0.0.1:' + str(edge.server_port)
        status, body, headers = self.http(origin, 'GET', '/api/objects/1', headers={'Cookie': self.sso.cookie_name + '=' + key,
                                                                                 'Origin': origin, 'X-Forwarded-Host': 'evil.invalid'})
        self.assertEqual(status, 403)
        self.assertEqual(body, b'{"error":"denied"}')
        self.assertIsNone(headers['Set-Cookie'])
        self.assertEqual(self.http(origin, 'HEAD', '/auth/session', headers={'Cookie': self.sso.cookie_name + '=' + key})[1], b'')


if __name__ == '__main__':
    unittest.main()
