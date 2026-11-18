"""Read-only, snapshot-based Linux /proc event adapter for synthetic testing."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone


HOST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def valid_host_id(value):
    return isinstance(value, str) and HOST_ID.fullmatch(value) is not None


class ProcSensor:
    """Observe a pinned service subtree without reading process data or sending traffic."""

    MAX_SEEN = 65536
    MAX_PROCESSES = 8192
    MAX_FDS_PER_PROCESS = 8192
    MAX_NETWORK_ROWS = 65536
    MAX_NETWORK_ROWS_PER_POLL = 65536
    MAX_PENDING_EVENTS = 4096
    MAX_CANARIES = 128
    RETAIN_SECONDS = 3600

    def __init__(self, proc_root, root_pid, root_start_ticks, sensor_id, tenant_id,
                 asset_id, service_id, workload_id, allowed_executables,
                 allowed_destinations, canaries):
        self.proc_root = Path(proc_root)
        self.root_pid = int(root_pid)
        self.root_start_ticks = int(root_start_ticks)
        if self.root_pid <= 0 or self.root_start_ticks <= 0:
            raise ValueError("pinned root PID and start ticks are required")
        self.sensor_id = str(sensor_id)
        self.tenant_id = str(tenant_id)
        self.asset_id = str(asset_id)
        self.service_id = str(service_id)
        self.workload_id = str(workload_id)
        if not all(valid_host_id(x) for x in (self.sensor_id, self.tenant_id, self.asset_id, self.service_id, self.workload_id)):
            raise ValueError("host IDs must match the event contract")
        self.allowed_executables = {Path(str(x)).name for x in allowed_executables}
        if any(not name or name in (".", "..") for name in self.allowed_executables):
            raise ValueError("executable names must be non-empty basenames")
        self.allowed_destinations = []
        for cidr, port in allowed_destinations:
            net = ipaddress.ip_network(str(cidr), strict=False)
            port = int(port)
            if not 1 <= port <= 65535:
                raise ValueError("destination port is invalid")
            self.allowed_destinations.append((net, port))
        if isinstance(canaries, dict):
            canaries = canaries.items()
        self.canaries = [(str(cid), Path(path)) for cid, path in canaries]
        if len(self.canaries) > self.MAX_CANARIES:
            raise ValueError("canary configuration exceeds capacity")
        if any(not valid_host_id(cid) for cid, _ in self.canaries):
            raise ValueError("canary IDs must match the event contract")
        self._boot_id = None
        self._root_cgroup = None
        self._seen = {}

    def poll(self, now=None):
        """Return (fixture-shaped event envelopes, bounded quality receipt)."""
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        now = now.astimezone(timezone.utc)
        now_ms = int(now.timestamp() * 1000)
        errors = Counter()
        events = []
        self._prune_seen(now.timestamp())

        boot_id = self._read_text(self.proc_root / "sys/kernel/random/boot_id", errors, "boot_id_unavailable")
        if boot_id is None:
            return events, self._receipt("not_evaluable", errors, 0)
        boot_id = boot_id.strip()
        if not boot_id or (self._boot_id is not None and boot_id != self._boot_id):
            errors["boot_id_changed"] += 1
            return events, self._receipt("not_evaluable", errors, 0)
        if self._boot_id is None:
            self._boot_id = boot_id

        uptime_text = self._read_text(self.proc_root / "uptime", errors, "uptime_unavailable")
        try:
            uptime = float(uptime_text.split()[0]) if uptime_text else None
            if uptime is None or not math.isfinite(uptime) or uptime < 0:
                raise ValueError()
        except (ValueError, IndexError):
            errors["uptime_invalid"] += 1
            return events, self._receipt("not_evaluable", errors, 0)

        root = self._read_process(self.root_pid, errors)
        if root is None:
            errors["root_unavailable"] += 1
            return events, self._receipt("not_evaluable", errors, 0)
        if root.start_ticks != self.root_start_ticks:
            errors["root_identity_mismatch"] += 1
            return events, self._receipt("not_evaluable", errors, 0)
        if self._root_cgroup is not None and root.cgroup != self._root_cgroup:
            errors["root_cgroup_changed"] += 1
            return events, self._receipt("not_evaluable", errors, 0)

        records = {root.pid: root}
        try:
            entries = []
            for path in self.proc_root.iterdir():
                if not path.name.isdecimal():
                    continue
                if len(entries) >= self.MAX_PROCESSES:
                    errors["process_capacity_rejected"] += 1
                    break
                entries.append(path)
        except OSError:
            errors["proc_enumeration_failed"] += 1
            return events, self._receipt("not_evaluable", errors, 0)
        for path in entries:
            pid = int(path.name)
            if pid == root.pid:
                continue
            rec = self._read_process(pid, errors)
            if rec is not None:
                records[pid] = rec

        descendants = {}
        for pid, rec in records.items():
            if pid == root.pid:
                continue
            status, parent, ancestry = self._verified_parent(rec, records, root)
            if status is None:
                errors["lineage_incomplete"] += 1
            elif status:
                descendants[pid] = (rec, parent, ancestry)

        staged_events = []
        staged_ids = set()
        network_budget = {"remaining": self.MAX_NETWORK_ROWS_PER_POLL, "reported": False}
        verified_count = 0
        for pid, (rec, parent, ancestry) in descendants.items():
            exe_path = self.proc_root / str(pid) / "exe"
            try:
                executable = Path(self._readlink(exe_path).removesuffix(" (deleted)")).name
                if not executable:
                    raise OSError()
            except (OSError, ValueError):
                errors["executable_unreadable"] += 1
                continue

            fd_dir = self.proc_root / str(pid) / "fd"
            try:
                fd_paths = []
                for fd_path in fd_dir.iterdir():
                    if len(fd_paths) >= self.MAX_FDS_PER_PROCESS:
                        errors["fd_capacity_rejected"] += 1
                        break
                    fd_paths.append(fd_path)
            except OSError:
                errors["fd_directory_unreadable"] += 1
                continue
            owned_sockets = set()
            regular_fds = []
            for fd_path in fd_paths:
                try:
                    target = self._readlink(fd_path)
                except OSError:
                    errors["fd_unreadable"] += 1
                    continue
                match = re.fullmatch(r"socket:\[(\d+)\]", target)
                if match:
                    owned_sockets.add(match.group(1))
                else:
                    regular_fds.append(fd_path)

            try:
                sockets = self._read_sockets(errors, pid, network_budget)
            except OSError:
                errors["network_table_unavailable"] += 1
                sockets = []

            process_key = self._process_key(boot_id, rec)
            parent_key = self._process_key(boot_id, parent)
            staged_for_process = []
            process_ids = set()

            def stage(envelope):
                event_id = envelope["event"]["event_id"]
                if event_id in self._seen or event_id in staged_ids or event_id in process_ids:
                    return
                if len(self._seen) + len(staged_ids) + len(process_ids) >= self.MAX_SEEN:
                    errors["capacity_rejected"] += 1
                    return
                if len(staged_ids) + len(process_ids) >= self.MAX_PENDING_EVENTS:
                    errors["pending_capacity_rejected"] += 1
                    return
                process_ids.add(event_id)
                staged_for_process.append(envelope)

            start_ms = int((now.timestamp() - uptime + rec.start_ticks / self._clock_ticks()) * 1000)
            if start_ms > now_ms or now_ms - start_ms > self.RETAIN_SECONDS * 1000:
                errors["process_start_time_out_of_window"] += 1
            else:
                classification = "expected_child" if executable in self.allowed_executables else "unexpected_child"
                ev = self._event(boot_id, rec, process_key, parent_key, "process_start",
                                 classification, "process", now_ms, start_ms)
                stage(ev)

            for row in sockets:
                if row["inode"] not in owned_sockets:
                    continue
                classification = "allowed_destination" if self._destination_allowed(row["address"], row["port"]) else "unapproved_destination"
                fingerprint = hashlib.sha256((row["address"] + ":" + str(row["port"])).encode("ascii")).hexdigest()
                ev = self._event(boot_id, rec, process_key, parent_key, "network_connect",
                                 classification, "network:" + fingerprint, now_ms, now_ms)
                stage(ev)

            if self.canaries:
                for canary_id, canary_path in self.canaries:
                    try:
                        canary_identity = self._stat_pair(canary_path)
                    except OSError:
                        errors["canary_stat_unavailable"] += 1
                        continue
                    for fd_path in regular_fds:
                        try:
                            if self._stat_pair(fd_path) != canary_identity:
                                continue
                        except OSError:
                            errors["fd_stat_unavailable"] += 1
                            continue
                        ev = self._event(boot_id, rec, process_key, parent_key, "canary_access",
                                         "canary", "canary:" + canary_id, now_ms, now_ms, canary_id)
                        stage(ev)
                        break

            # Revalidate every ancestor after all executable, fd, net and canary reads.
            if not all(self._still_same(item) for item in ancestry):
                errors["pid_changed_during_snapshot"] += 1
                continue
            verified_count += 1
            staged_events.extend(staged_for_process)
            staged_ids.update(process_ids)

        root_check = self._read_process(self.root_pid, errors)
        if root_check is None or root_check.start_ticks != self.root_start_ticks or root_check.cgroup != root.cgroup:
            errors["root_changed_during_snapshot"] += 1
            staged_events = []
        else:
            if self._root_cgroup is None:
                self._root_cgroup = root.cgroup
            for envelope in staged_events:
                self._append_event(events, envelope, now.timestamp(), errors)
        status = "ok" if not errors else "not_evaluable"
        if any(key.endswith("capacity_rejected") for key in errors):
            status = "capacity_rejected"
        return events, self._receipt(status, errors, verified_count)

    def _receipt(self, status, errors, verified_descendants):
        return {
            "mode": "snapshot_only",
            "status": status,
            "missed_short_lived_possible": True,
            "network_time_semantics": "first observed in a snapshot; does not prove syscall time",
            "verified_descendants": int(verified_descendants),
            "errors": dict(sorted(errors.items())),
        }

    def _read_text(self, path, errors, error_key):
        try:
            return Path(path).read_text(encoding="ascii")
        except (OSError, UnicodeError):
            errors[error_key] += 1
            return None

    def _read_process(self, pid, errors):
        base = self.proc_root / str(pid)
        text = self._read_text(base / "stat", errors, "process_stat_unavailable")
        if text is None:
            return None
        try:
            # comm is parenthesized and may itself contain spaces or ')' characters.
            close = text.rfind(")")
            if close < 0:
                raise ValueError()
            fields = text[close + 1:].split()
            ppid = int(fields[1])
            start_ticks = int(fields[19])
            if ppid < 0 or start_ticks <= 0:
                raise ValueError()
        except (ValueError, IndexError):
            errors["process_stat_invalid"] += 1
            return None
        cgroup_text = self._read_text(base / "cgroup", errors, "cgroup_unavailable")
        if cgroup_text is None:
            return None
        cgroup = tuple(sorted(line.strip() for line in cgroup_text.splitlines() if line.strip()))
        if not cgroup:
            errors["cgroup_invalid"] += 1
            return None
        return _Process(pid=pid, ppid=ppid, start_ticks=start_ticks, cgroup=cgroup)

    def _verified_parent(self, rec, records, root):
        if rec.cgroup != root.cgroup:
            return False, None, []
        current = rec
        direct_parent = records.get(rec.ppid)
        chain = [rec]
        seen = set()
        for _ in range(256):
            if current.pid in seen:
                return False, None, []
            seen.add(current.pid)
            if current.pid == root.pid:
                return current.start_ticks == root.start_ticks, direct_parent, chain
            if current.ppid <= 0:
                return False, None, []
            parent = records.get(current.ppid)
            if parent is None:
                return None, None, []
            if parent.cgroup != root.cgroup:
                return False, None, []
            chain.append(parent)
            current = parent
        return None, None, []

    def _still_same(self, rec):
        errors = Counter()
        current = self._read_process(rec.pid, errors)
        return current is not None and current.ppid == rec.ppid and current.start_ticks == rec.start_ticks and current.cgroup == rec.cgroup

    def _process_key(self, boot_id, rec):
        return f"{boot_id}:{rec.pid}:{rec.start_ticks}"

    def _clock_ticks(self):
        # The CLI is Linux-only; the fallback keeps fake-proc tests portable.
        return int(os.sysconf("SC_CLK_TCK")) if hasattr(os, "sysconf") else 100

    def _readlink(self, path):
        return os.readlink(path)

    def _stat_pair(self, path):
        stat = os.stat(path)
        return stat.st_dev, stat.st_ino

    def _read_sockets(self, errors, namespace_pid, budget):
        result = []
        for filename, family in (("tcp", 4), ("tcp6", 6)):
            if budget["remaining"] <= 0:
                if not budget["reported"]:
                    errors["network_capacity_rejected"] += 1
                    budget["reported"] = True
                return result
            path = self.proc_root / str(namespace_pid) / "net" / filename
            try:
                with path.open("r", encoding="ascii") as stream:
                    next(stream, None)
                    for row_number, line in enumerate(stream):
                        if row_number >= self.MAX_NETWORK_ROWS or budget["remaining"] <= 0:
                            errors["network_capacity_rejected"] += 1
                            budget["reported"] = True
                            return result
                        budget["remaining"] -= 1
                        fields = line.split()
                        try:
                            if len(fields) < 10 or fields[3] not in ("01", "02"):
                                continue
                            address, port = self._decode_endpoint(fields[2], family)
                            result.append({"address": address, "port": port, "inode": fields[9]})
                        except (ValueError, IndexError):
                            errors["network_row_invalid"] += 1
            except (OSError, UnicodeError):
                errors["network_table_unavailable"] += 1
        return result

    @staticmethod
    def _decode_endpoint(encoded, family):
        if ":" not in encoded:
            raise ValueError("endpoint missing port")
        raw_address, raw_port = encoded.rsplit(":", 1)
        port = int(raw_port, 16)
        if family == 4:
            if len(raw_address) != 8:
                raise ValueError("invalid IPv4 encoding")
            packed = bytes.fromhex(raw_address)[::-1]
        elif family == 6:
            if len(raw_address) != 32:
                raise ValueError("invalid IPv6 encoding")
            raw = bytes.fromhex(raw_address)
            packed = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        else:
            raise ValueError("unsupported address family")
        return str(ipaddress.ip_address(packed)), port

    def _destination_allowed(self, address, port):
        ip = ipaddress.ip_address(address)
        return any(ip.version == net.version and ip in net and port == allowed_port
                   for net, allowed_port in self.allowed_destinations)

    def _event(self, boot_id, rec, process_key, parent_key, kind, classification,
               fingerprint, arrival_ms, event_ms, canary_id=None):
        seed = "|".join((self.sensor_id, self.tenant_id, self.asset_id, self.service_id, self.workload_id, boot_id,
                         process_key, kind, fingerprint))
        event_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        event = {
            "schema_version": "host/1.0",
            "event_id": event_id,
            "sensor_id": self.sensor_id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "event_type": kind,
            "service_id": self.service_id,
            "workload_id": self.workload_id,
            "process_key": process_key,
            "parent_key": parent_key,
            "lineage": "verified",
            "classification": classification,
            "data_quality": "complete",
            "request_id": "",
        }
        if kind == "canary_access":
            event["canary_id"] = canary_id
        return {"event_ms": int(event_ms), "arrival_ms": int(arrival_ms), "event": event}

    def _append_event(self, events, envelope, now_seconds, errors):
        event_id = envelope["event"]["event_id"]
        if event_id in self._seen:
            return
        if len(self._seen) >= self.MAX_SEEN:
            errors["capacity_rejected"] += 1
            return
        self._seen[event_id] = now_seconds
        events.append(envelope)

    def _prune_seen(self, now_seconds):
        cutoff = now_seconds - self.RETAIN_SECONDS
        for event_id, seen_at in list(self._seen.items()):
            if seen_at < cutoff:
                del self._seen[event_id]


def to_wire(envelope):
    """Convert a fixture-shaped event envelope to collector host.Event JSON."""
    event = dict(envelope["event"])
    def rfc3339(epoch_ms):
        return datetime.fromtimestamp(epoch_ms / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    event["event_time"] = rfc3339(envelope["event_ms"])
    event["ingest_time"] = rfc3339(envelope["arrival_ms"])
    return event


@dataclass
class _Process:
    pid: int
    ppid: int
    start_ticks: int
    cgroup: tuple


def _parse_destination(value):
    try:
        cidr, raw_port = value.rsplit(":", 1)
        return cidr, int(raw_port)
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError("destination must be CIDR:PORT") from exc


def _parse_canary(value):
    if "=" not in value:
        raise argparse.ArgumentTypeError("canary must be OPAQUE_ID=PATH")
    canary_id, path = value.split("=", 1)
    if not canary_id or not path:
        raise argparse.ArgumentTypeError("canary must be OPAQUE_ID=PATH")
    return canary_id, path


def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Read-only /proc snapshot; --out is new-file, one normalized host.Event JSON object per line "
        "(event_time and ingest_time are RFC3339 UTC); bounded quality receipt is printed to stderr"))
    parser.add_argument("--root-pid", type=int, required=True)
    parser.add_argument("--root-start-ticks", type=int, required=True)
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--workload-id", required=True)
    parser.add_argument("--allowed-executable", action="append", default=[])
    parser.add_argument("--allow-destination", action="append", type=_parse_destination, default=[])
    parser.add_argument("--canary", action="append", type=_parse_canary, default=[])
    parser.add_argument("--proc-root", default="/proc")
    parser.add_argument("--out", required=True, help="new JSONL output path; existing files are rejected")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux"):
        parser.error("the CLI runs only on Linux")
    try:
        sensor = ProcSensor(args.proc_root, args.root_pid, args.root_start_ticks, args.sensor_id,
                            args.tenant_id, args.asset_id, args.service_id, args.workload_id,
                            args.allowed_executable, args.allow_destination, args.canary)
        events, receipt = sensor.poll()
        with open(args.out, "x", encoding="utf-8", newline="\n") as output:
            for envelope in events:
                output.write(json.dumps(to_wire(envelope), sort_keys=True, separators=(",", ":")) + "\n")
        print(json.dumps(receipt, sort_keys=True), file=sys.stderr)
        return 0 if receipt["status"] == "ok" else 2
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
