"""Explicit single-workload Linux nftables adapter; no Docker/host API access.

The registered network namespace is the entire mutation boundary. An inet set
combines an absolute (conservatively second-rounded) cutoff with a kernel
timeout, so neither controller nor adapter availability renews the isolation.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time

UTC = timezone.utc
BINDING = ('action_id', 'case_id', 'workload_id', 'tenant_id', 'asset_id',
           'issued_at', 'expires_at', 'idempotency_key', 'command_hash')
LEASE_KEYS = set(BINDING) | {'state', 'release_requested', 'unknown_reason'}


def packed(v):
    return json.dumps(v, separators=(',', ':'), ensure_ascii=True).encode()


def digest(v):
    return hashlib.sha256(packed(v)).hexdigest()


def strict(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out or key != key.lower():
                raise ValueError('duplicate or noncanonical field')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def timestamp(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('UTC lease timestamp required')
    return datetime.fromisoformat(value[:-1] + '+00:00').timestamp()


def scope_sha(c):
    return digest([c['schema'], c['agent_id'], c['network_namespace'], c['boot_id'],
                   c['tenant_id'], c['asset_id'], c['workload_id'], c['interface'],
                   str(c['interface_index']), c['management_ipv4'], str(c['management_port'])])


def validate_scope(c):
    keys = {'schema', 'agent_id', 'network_namespace', 'boot_id', 'tenant_id', 'asset_id',
            'workload_id', 'interface', 'interface_index', 'management_ipv4', 'management_port'}
    if set(c) != keys or c['schema'] != 'linux-isolation-scope/1':
        raise ValueError('fixed Linux scope required')
    for key in ('tenant_id', 'asset_id', 'workload_id'):
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', c[key]):
            raise ValueError('bounded workload identity required')
    if (not re.fullmatch('[a-f0-9]{32}', c['agent_id'])
            or not re.fullmatch(r'net:\[[0-9]+\]', c['network_namespace'])
            or not re.fullmatch('[a-f0-9-]{36}', c['boot_id'])
            or not re.fullmatch('[A-Za-z0-9_]{1,15}', c['interface']) or c['interface'] == 'lo'
            or type(c['interface_index']) is not int or c['interface_index'] < 1
            or type(c['management_port']) is not int or not 1 <= c['management_port'] <= 65535):
        raise ValueError('pinned namespace/interface/management scope required')
    ip = ipaddress.ip_address(c['management_ipv4'])
    if ip.version != 4 or ip.is_loopback or ip.is_unspecified or ip.is_multicast or str(ip) != c['management_ipv4']:
        raise ValueError('exact management IPv4 required')


def validate_lease(a, c):
    if not isinstance(a, dict) or set(a) - LEASE_KEYS or not set(BINDING).issubset(a) or 'state' not in a:
        raise ValueError('exact typed lease required')
    for key in ('case_id', 'workload_id', 'tenant_id', 'asset_id', 'idempotency_key'):
        if not isinstance(a[key], str) or not re.fullmatch('[A-Za-z0-9_.:-]{1,128}', a[key]):
            raise ValueError('invalid lease identity')
    if any(a[k] != c[k] for k in ('workload_id', 'tenant_id', 'asset_id')):
        raise ValueError('lease outside pinned namespace scope')
    issued, expires = timestamp(a['issued_at']), timestamp(a['expires_at'])
    ttl = round(expires - issued)
    if not 1 <= ttl <= 60 or abs(expires - issued - ttl) > .000001:
        raise ValueError('fixed integral bounded lease TTL required')
    h = digest({'idempotency_key': a['idempotency_key'], 'case_id': a['case_id'], 'ttl_seconds': ttl})
    if a['command_hash'] != h or a['action_id'] != 'isolate-' + h[:32]:
        raise ValueError('lease command binding mismatch')
    if a['state'] not in ('pending', 'active', 'unknown', 'releasing', 'released', 'expired', 'not_applied'):
        raise ValueError('invalid lease state')
    return issued, expires


class Kernel:
    def __init__(self, scope, nft='/usr/sbin/nft'):
        self.c = scope
        self.nft = nft
        self.table = 'ra_i_' + scope['agent_id'][:16]

    def runtime(self):
        if sys.platform != 'linux' or os.readlink('/proc/self/ns/net') != self.c['network_namespace']:
            raise ValueError('network namespace identity changed')
        if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != self.c['boot_id']:
            raise ValueError('kernel boot identity changed')
        interfaces = dict(socket.if_nameindex())
        if set(interfaces.values()) != {'lo', self.c['interface']} or interfaces.get(self.c['interface_index']) != self.c['interface']:
            raise ValueError('unregistered or replaced workload interface')

    def run(self, *args, script=None):
        self.runtime()
        result = subprocess.run([self.nft, *args], input=script.encode() if script is not None else None,
                                capture_output=True, timeout=.75, env=os.environ | {'TZ': 'UTC', 'LC_ALL': 'C'})
        if result.returncode or len(result.stdout) > 65536:
            raise ValueError('bounded nftables operation failed; outcome unknown')
        return result.stdout

    def create(self):
        c, table = self.c, self.table
        script = (f'create table inet {table}\n'
                  f'add set inet {table} active {{ typeof meta nfproto . meta time; flags interval,timeout; size 4; }}\n'
                  f'add chain inet {table} inbound {{ type filter hook input priority -150; policy accept; }}\n'
                  f'add rule inet {table} inbound iifname "lo" accept\n'
                  f'add rule inet {table} inbound iifname "{c["interface"]}" ip saddr {c["management_ipv4"]} tcp dport {c["management_port"]} accept\n'
                  f'add rule inet {table} inbound meta nfproto . meta time @active drop\n'
                  f'add chain inet {table} outbound {{ type filter hook output priority -150; policy accept; }}\n'
                  f'add rule inet {table} outbound oifname "lo" ip daddr != 127.0.0.11 accept\n'
                  f'add rule inet {table} outbound oifname "lo" ip6 daddr ::1 accept\n'
                  f'add rule inet {table} outbound oifname "{c["interface"]}" ip daddr {c["management_ipv4"]} tcp sport {c["management_port"]} ct state established accept\n'
                  f'add rule inet {table} outbound meta nfproto . meta time @active drop\n')
        self.run('-f', '-', script=script)

    def inspect(self):
        data = strict(self.run('-j', 'list', 'table', 'inet', self.table))
        objects, elements = [], []
        sets = 0
        def handles(v):
            if isinstance(v, dict):
                return {k: handles(x) for k, x in v.items() if k != 'handle'}
            if isinstance(v, list):
                return [handles(x) for x in v]
            return v
        for obj in data['nftables']:
            if 'metainfo' in obj:
                continue
            if 'set' in obj:
                sets += 1
                if obj['set']['name'] != 'active':
                    raise ValueError('unknown namespace set')
                elements = obj['set'].pop('elem', [])
            objects.append(handles(obj))
        if sets != 1 or len(elements) > 2:
            raise ValueError('unexpected kernel lease capacity')
        # Sort JSON object keys but retain rule/statement order.
        fingerprint = hashlib.sha256(json.dumps(objects, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return fingerprint, elements

    def install(self, expires):
        # The absolute guard prevents command/queue delay extending Expires;
        # the monotonic kernel timeout prevents wall-clock rollback revival.
        millis = math.ceil((expires - time.time()) * 1000)
        if millis <= 0 or millis > 60000:
            raise ValueError('fresh fixed kernel deadline required')
        end = datetime.fromtimestamp(math.floor(expires), UTC).strftime('%Y-%m-%d %H:%M:%S')
        if math.floor(expires) <= time.time():
            raise ValueError('too little lease lifetime for conservative kernel cutoff')
        entries = ', '.join(f'{family} . "2020-01-01 00:00:00"-"{end}" timeout {millis}ms' for family in ('ipv4', 'ipv6'))
        script = f'flush set inet {self.table} active\nadd element inet {self.table} active {{ {entries} }}\n'
        self.run('-f', '-', script=script)

    def release(self):
        self.run('-f', '-', script=f'flush set inet {self.table} active\n')

    def validate_element(self, elements, entry):
        if not elements:
            return False
        if entry is None:
            raise ValueError('kernel effect without journal ownership')
        end = datetime.fromtimestamp(math.floor(timestamp(entry['lease']['expires_at'])), UTC).strftime('%Y-%m-%d %H:%M:%S')
        families = set()
        for element in elements:
            e = element['elem']
            family = e['val']['concat'][0]
            if (family not in ('ipv4', 'ipv6') or family in families
                    or e['val'] != {'concat': [family, {'range': ['2020-01-01 00:00:00', end]}]}
                    or set(e) - {'val', 'timeout', 'expires'} or not 0 <= e.get('expires', -1) <= 61
                    or not 0 < e.get('timeout', 0) <= 60):
                raise ValueError('kernel lease binding changed')
            families.add(family)
        if families != {'ipv4', 'ipv6'}:
            raise ValueError('incomplete dual-stack kernel lease')
        return True


class Registry:
    def close(self):
        for name in ('file', 'owner'):
            handle = getattr(self, name, None)
            if handle is not None:
                handle.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __init__(self, directory, scope, kernel):
        validate_scope(scope)
        self.scope, self.sha, self.kernel = scope, scope_sha(scope), kernel
        self.mu = threading.RLock()
        self.entries, self.current, self.structure = {}, None, None
        self.seq, self.head, self.last, self.poisoned = 0, '', 0, False
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise ValueError('regular owned adapter directory required')
        self.path = directory / 'isolation.jsonl'
        lock = directory / 'owner.lock'
        for path in (self.path, lock):
            if path.is_symlink() or path.exists() and (not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 1 << 20):
                raise ValueError('bounded regular adapter journal required')
        self.owner = open(lock, 'a+b')
        fcntl.flock(self.owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        existed = self.path.exists()
        self.file = open(self.path, 'a+b', buffering=0)
        self.file.seek(0)
        raw = self.file.read((1 << 20) + 1)
        if len(raw) > 1 << 20 or raw and not raw.endswith(b'\n'):
            raise ValueError('incomplete adapter journal retained')
        for line in raw.splitlines():
            row = strict(line)
            got = row.pop('sha256')
            if (set(row) != {'sequence', 'previous_sha256', 'scope_sha256', 'at', 'kind', 'payload'}
                    or got != digest(row) or row['sequence'] != self.seq + 1 or row['previous_sha256'] != self.head
                    or row['scope_sha256'] != self.sha or row['at'] < self.last):
                raise ValueError('invalid adapter journal chain')
            self.transition(row['kind'], row['payload'])
            self.seq, self.head, self.last = row['sequence'], got, row['at']
        self.ready()
        if not existed:
            # The caller must provide a new namespace/table. Existing tables
            # are never adopted or flushed after losing their journal.
            self.kernel.create()
            structure, elems = self.kernel.inspect()
            if elems:
                raise ValueError('fresh adapter table was not empty')
            self.append('initialize', {'structure_sha256': structure})
        self.inspect()

    def ready(self):
        if self.poisoned or time.time() < self.last:
            raise ValueError('adapter unavailable or clock moved backwards')
        self.kernel.runtime()

    def transition(self, kind, payload):
        if kind == 'initialize':
            if self.structure is not None or set(payload) != {'structure_sha256'} or not re.fullmatch('[a-f0-9]{64}', payload['structure_sha256']):
                raise ValueError('invalid adapter initialization')
            self.structure = payload['structure_sha256']
            return
        if self.structure is None or set(payload) != {'lease'}:
            raise ValueError('initialized bounded adapter record required')
        a = payload['lease']
        validate_lease(a, self.scope)
        ident = a['action_id']
        old = self.entries.get(ident)
        if kind == 'intent':
            if old or len(self.entries) >= 64 or a['state'] != 'pending':
                raise ValueError('duplicate adapter intent')
            self.entries[ident] = {'lease': a, 'phase': 'pending'}
            self.current = ident
        else:
            if old is None or any(old['lease'][k] != a[k] for k in BINDING):
                raise ValueError('adapter lease binding changed')
            if kind == 'applied' and old['phase'] == 'pending':
                old['phase'] = 'applied'
            elif kind == 'release_intent' and old['phase'] in ('pending', 'applied'):
                old['phase'] = 'release_pending'
            elif kind == 'released' and old['phase'] == 'release_pending':
                old['phase'] = 'released'
            else:
                raise ValueError('adapter resurrection or repeated effect')

    def append(self, kind, payload):
        self.ready()
        if self.seq >= 256:
            raise ValueError('adapter journal record capacity')
        row = {'sequence': self.seq + 1, 'previous_sha256': self.head, 'scope_sha256': self.sha,
               'at': time.time(), 'kind': kind, 'payload': payload}
        h = digest(row)
        data = packed(row | {'sha256': h}) + b'\n'
        if self.file.seek(0, 2) + len(data) > 1 << 20:
            raise ValueError('adapter journal byte capacity')
        try:
            if self.file.write(data) != len(data):
                raise OSError('partial adapter record')
            os.fsync(self.file.fileno())
            self.transition(kind, payload)
        except Exception:
            self.poisoned = True
            raise
        self.seq, self.head, self.last = row['sequence'], h, row['at']

    def inspect(self):
        self.ready()
        shape, elems = self.kernel.inspect()
        if self.structure is None or shape != self.structure:
            raise ValueError('namespace ruleset changed or history lost')
        entry = self.entries.get(self.current)
        present = self.kernel.validate_element(elems, entry)
        if present and entry['phase'] == 'released':
            raise ValueError('released kernel lease resurrected')
        return present

    def status(self, a):
        with self.mu:
            _, expires = validate_lease(a, self.scope)
            present = self.inspect()
            entry = self.entries.get(a['action_id'])
            out = dict(a)
            out.pop('unknown_reason', None)
            if entry is None:
                current = self.entries.get(self.current)
                if present and current and time.time() < timestamp(current['lease']['expires_at']):
                    raise ValueError('workload already has another kernel lease')
                out['state'] = 'not_applied'
            else:
                if any(entry['lease'][k] != a[k] for k in BINDING):
                    raise ValueError('queried lease binding changed')
                if entry['phase'] == 'released':
                    out['state'] = 'released'
                elif time.time() >= expires:
                    # Both the absolute match cutoff and full table structure
                    # are verified, even if GC has not removed the set element.
                    out['state'] = 'expired'
                elif present and self.current == a['action_id'] and time.time() < math.floor(expires):
                    out['state'] = 'active'
                else:
                    # A conservative subsecond cutoff, missing element, or
                    # incomplete attempt is unknown; never absence/retry.
                    out['state'] = 'unknown'
            return out

    def apply(self, a):
        with self.mu:
            issued, expires = validate_lease(a, self.scope)
            now = time.time()
            if a['state'] != 'pending' or a.get('release_requested') or issued > now or now >= math.floor(expires):
                raise ValueError('fresh pending fixed lease required')
            self.inspect()
            if a['action_id'] in self.entries:
                raise ValueError('attempt already recorded; query only')
            if len(self.entries) >= 64:
                raise ValueError('adapter entry capacity')
            current = self.entries.get(self.current)
            if current and current['phase'] != 'released' and now < timestamp(current['lease']['expires_at']):
                raise ValueError('unresolved workload lease')
            self.append('intent', {'lease': a})
            self.kernel.install(expires)
            if self.status(a)['state'] != 'active':
                raise ValueError('kernel apply not confirmed')
            self.append('applied', {'lease': a})
            return self.status(a)

    def release(self, ident):
        with self.mu:
            if not isinstance(ident, str) or ident not in self.entries:
                raise ValueError('known exact action required')
            entry = self.entries[ident]
            a = entry['lease']
            before = self.status(a)
            if before['state'] in ('released', 'expired'):
                return before
            if before['state'] != 'active' or entry['phase'] == 'release_pending':
                raise ValueError('release already attempted or effect unknown')
            self.append('release_intent', {'lease': a})
            self.kernel.release()
            if self.inspect():
                raise ValueError('kernel release not confirmed')
            self.append('released', {'lease': a})
            return self.status(a)


def serve(scope_path, directory, socket_path):
    if sys.platform != 'linux':
        raise ValueError('Linux only')
    scope = strict(Path(scope_path).read_bytes())
    read, write = os.environ.get('RA_LINUX_ADAPTER_READ_TOKEN', ''), os.environ.get('RA_LINUX_ADAPTER_WRITE_TOKEN', '')
    if len(read) < 32 or len(write) < 32 or read == write:
        raise ValueError('distinct adapter credentials required')
    registry = Registry(directory, scope, Kernel(scope))
    slots = threading.BoundedSemaphore(4)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            import hmac
            expected = read if self.path == '/v1/status' else write
            if (len(self.headers.get_all('Authorization', [])) != 1
                    or not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + expected)):
                self.send_error(401, 'authentication required')
                return
            if self.path not in ('/v1/status', '/v1/apply', '/v1/release') or self.headers.get('Transfer-Encoding'):
                self.send_error(400, 'typed adapter operation required')
                return
            if not slots.acquire(False):
                self.send_error(429, 'adapter capacity')
                return
            try:
                self.connection.settimeout(1)
                size = int(self.headers.get('Content-Length', '0'))
                if not 1 <= size <= 8192:
                    raise ValueError('bounded command required')
                a = strict(self.rfile.read(size))
                if self.path == '/v1/release':
                    if set(a) != {'action_id'}:
                        raise ValueError('exact release ID required')
                    result = registry.release(a['action_id'])
                else:
                    result = registry.status(a) if self.path == '/v1/status' else registry.apply(a)
                raw = packed({'schema': 'linux-isolation-reply/1', 'scope_sha256': registry.sha, 'lease': result})
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except Exception:
                self.send_error(503, 'adapter state unavailable or operation rejected')
            finally:
                slots.release()

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
    path = Path(socket_path)
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode):
            raise ValueError('refusing to replace non-socket')
        # Only this exact registered socket is replaced after exclusive journal
        # ownership, never a recursive filesystem removal.
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    with Server(str(path), Handler) as server:
        os.chmod(path, 0o600)
        server.serve_forever(poll_interval=.1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--scope', required=True)
    parser.add_argument('--state', required=True)
    parser.add_argument('--socket', required=True)
    args = parser.parse_args()
    try:
        serve(args.scope, args.state, args.socket)
    except Exception as error:
        # Deployment paths, credentials and nft command text are not logged.
        reason = ': ' + str(error) if isinstance(error, ValueError) else ''
        print('Linux isolation adapter unavailable: ' + type(error).__name__ + reason, file=sys.stderr)
        raise SystemExit(2)
