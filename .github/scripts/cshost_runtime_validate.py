#!/usr/bin/env python3
"""Fail-closed CSHOST runtime validation with FTP overlay and mandatory rollback."""

from __future__ import annotations

import argparse
import datetime as dt
import ftplib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import struct
import sys
import time
from typing import Protocol
import urllib.parse
import urllib.request
import zipfile


REPORT_SCHEMA = "https://github.com/bywinsty/cs2-vip/runtime-validation/v4"
PROBE_SCHEMA = "https://github.com/bywinsty/cs2-vip/runtime-probe/v2"
SENTINEL_SCHEMA = "https://github.com/bywinsty/cs2-vip/cshost-runtime-sentinel/v4"
JOURNAL_SCHEMA = "https://github.com/bywinsty/cs2-vip/cshost-runtime-journal/v4"
LEGACY_JOURNAL_SCHEMA = "https://github.com/bywinsty/cs2-vip/cshost-runtime-journal/v3"
SENTINEL_PATH = ".vip-ci/runtime-sentinel-v4.json"
JOURNAL_PATH = ".vip-ci/runtime-overlay-journal-v4.json"
LEGACY_JOURNAL_PATH = ".vip-ci/runtime-overlay-journal-v3.json"
PLUGIN_PATH = "addons/vip/vip.so"
EVIDENCE_DIRECTORY = "addons/data"
REQUIRED_CAPABILITIES = frozenset({"metamod", "utils", "menus", "players", "sqlmm"})
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")


class ValidationError(RuntimeError):
    """Expected fail-closed validation error."""


class Transport(Protocol):
    """Minimal remote file contract used by validation and recovery."""

    def exists(self, path: str) -> bool: ...
    def download(self, path: str) -> bytes: ...
    def upload_atomic(self, path: str, payload: bytes) -> None: ...
    def rename(self, source: str, destination: str) -> None: ...
    def delete(self, path: str, *, missing_ok: bool = False) -> None: ...


def utc_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "REPLACE_ME" in value.upper():
        raise ValidationError(f"{field} must be a non-placeholder string")
    return value.strip()


def require_sha256(value: object, field: str) -> str:
    value = require_text(value, field).lower()
    if not SHA256_RE.fullmatch(value) or value == "0" * 64:
        raise ValidationError(f"{field} must be a non-zero lowercase SHA-256")
    return value


def remote_path(value: object, field: str) -> str:
    value = require_text(value, field)
    if "\\" in value:
        raise ValidationError(f"{field} must be a POSIX relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValidationError(f"{field} must remain below the FTP root")
    return pure.as_posix()


def load_sentinel(raw: bytes, expected_sha256: str) -> dict:
    if sha256_bytes(raw) != require_sha256(expected_sha256, "sentinel SHA-256"):
        raise ValidationError("remote runtime sentinel SHA-256 does not match the protected value")
    try:
        config = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"runtime sentinel is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(config, dict) or config.get("schema") != SENTINEL_SCHEMA:
        raise ValidationError("runtime sentinel schema is not v4")
    if config.get("purpose") != "vip-ci-test-server" or config.get("production") is not False:
        raise ValidationError("runtime sentinel does not identify a non-production VIP CI server")
    if remote_path(config.get("plugin_path"), "sentinel.plugin_path") != PLUGIN_PATH:
        raise ValidationError(f"sentinel.plugin_path must be exactly {PLUGIN_PATH}")
    if remote_path(config.get("evidence_directory"), "sentinel.evidence_directory") != EVIDENCE_DIRECTORY:
        raise ValidationError(f"sentinel.evidence_directory must be exactly {EVIDENCE_DIRECTORY}")
    stage_id = require_sha256(config.get("stage_id"), "sentinel.stage_id")
    config["stage_id"] = stage_id
    for name in ("startup_timeout_seconds", "shutdown_timeout_seconds", "probe_timeout_seconds"):
        value = config.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not 10 <= value <= 600:
            raise ValidationError(f"sentinel.{name} must be an integer from 10 to 600")
    a2s = config.get("a2s")
    if not isinstance(a2s, dict):
        raise ValidationError("sentinel.a2s must be an object")
    a2s["host"] = require_text(a2s.get("host"), "sentinel.a2s.host")
    if isinstance(a2s.get("port"), bool) or not isinstance(a2s.get("port"), int) or not 1 <= a2s["port"] <= 65535:
        raise ValidationError("sentinel.a2s.port must be a valid port")
    dependencies = config.get("runtime_dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValidationError("sentinel.runtime_dependencies must be a non-empty array")
    seen_capabilities: set[str] = set()
    seen_paths: set[str] = set()
    normalized = []
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            raise ValidationError(f"runtime_dependencies[{index}] must be an object")
        capability = require_text(dependency.get("capability"), f"runtime_dependencies[{index}].capability").lower()
        if capability in seen_capabilities:
            raise ValidationError(f"duplicate runtime capability: {capability}")
        path = remote_path(dependency.get("path"), f"runtime_dependencies[{index}].path")
        if path in seen_paths or not path.startswith("addons/") or not path.endswith(".so"):
            raise ValidationError(f"invalid or duplicate runtime dependency path: {path}")
        if "/configs/" in f"/{path}" or "databases.cfg" in path or path.startswith("addons/data/"):
            raise ValidationError(f"runtime dependency path is sensitive: {path}")
        seen_capabilities.add(capability)
        seen_paths.add(path)
        normalized.append({
            "capability": capability,
            "name": require_text(dependency.get("name"), f"runtime_dependencies[{index}].name"),
            "version": require_text(dependency.get("version"), f"runtime_dependencies[{index}].version"),
            "path": path,
            "sha256": require_sha256(dependency.get("sha256"), f"runtime_dependencies[{index}].sha256"),
            "optional": dependency.get("optional") is True,
        })
    missing = REQUIRED_CAPABILITIES - seen_capabilities
    if missing:
        raise ValidationError(f"runtime sentinel is missing required capabilities: {sorted(missing)}")
    config["runtime_dependencies"] = normalized
    return config


class FTPTransport:
    def __init__(self, host: str, port: int, user: str, password: str, root: str, timeout: int = 30):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.root = root
        self.timeout = timeout
        self.connection: ftplib.FTP | None = None

    def __enter__(self) -> "FTPTransport":
        connection = ftplib.FTP()
        try:
            connection.connect(self.host, self.port, timeout=self.timeout)
            connection.login(self.user, self.password)
            connection.set_pasv(True)
            if self.root not in {"", "."}:
                connection.cwd(self.root)
        except ftplib.all_errors as exc:
            try:
                connection.close()
            except OSError:
                pass
            raise ValidationError(f"FTP preflight failed: {type(exc).__name__}") from exc
        self.connection = connection
        return self

    def __exit__(self, *_: object) -> None:
        if self.connection is not None:
            try:
                self.connection.quit()
            except ftplib.all_errors:
                self.connection.close()

    @property
    def ftp(self) -> ftplib.FTP:
        if self.connection is None:
            raise ValidationError("FTP connection is not open")
        return self.connection

    def mkdirs(self, path: str) -> None:
        parent = PurePosixPath(remote_path(path, "remote directory"))
        current = ""
        for part in parent.parts:
            current = f"{current}/{part}" if current else part
            try:
                self.ftp.mkd(current)
            except ftplib.error_perm as exc:
                if not str(exc).startswith("550"):
                    raise ValidationError(f"FTP cannot create directory {current}") from exc

    def exists(self, path: str) -> bool:
        path = remote_path(path, "remote path")
        try:
            self.ftp.sendcmd("TYPE I")
            self.ftp.size(path)
            return True
        except ftplib.error_perm as exc:
            if str(exc).startswith("550"):
                return False
            raise ValidationError(f"FTP cannot inspect {path}") from exc

    def download(self, path: str) -> bytes:
        path = remote_path(path, "download path")
        output = io.BytesIO()
        try:
            self.ftp.retrbinary(f"RETR {path}", output.write)
        except ftplib.all_errors as exc:
            raise ValidationError(f"FTP download failed for {path}: {type(exc).__name__}") from exc
        return output.getvalue()

    def upload_atomic(self, path: str, payload: bytes) -> None:
        path = remote_path(path, "upload path")
        parent = PurePosixPath(path).parent.as_posix()
        if parent != ".":
            self.mkdirs(parent)
        temporary = f"{path}.upload-{secrets.token_hex(8)}"
        previous = f"{path}.previous-{secrets.token_hex(8)}"
        moved_previous = False
        try:
            self.ftp.storbinary(f"STOR {temporary}", io.BytesIO(payload))
            if self.download(temporary) != payload:
                raise ValidationError(f"FTP upload verification failed for {path}")
            if self.exists(path):
                self.ftp.rename(path, previous)
                moved_previous = True
            self.ftp.rename(temporary, path)
            if moved_previous:
                self.ftp.delete(previous)
        except (ftplib.all_errors, ValidationError) as exc:
            try:
                self.ftp.delete(temporary)
            except ftplib.all_errors:
                pass
            if moved_previous:
                try:
                    if self.exists(path):
                        self.ftp.delete(path)
                    self.ftp.rename(previous, path)
                except (ftplib.all_errors, ValidationError):
                    pass
            if isinstance(exc, ValidationError):
                raise
            raise ValidationError(f"FTP atomic upload failed for {path}: {type(exc).__name__}") from exc

    def upload_json(self, path: str, value: dict) -> None:
        self.upload_atomic(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())

    def rename(self, source: str, destination: str) -> None:
        source = remote_path(source, "rename source")
        destination = remote_path(destination, "rename destination")
        parent = PurePosixPath(destination).parent.as_posix()
        if parent != ".":
            self.mkdirs(parent)
        try:
            self.ftp.rename(source, destination)
        except ftplib.all_errors as exc:
            raise ValidationError(f"FTP rename failed: {source} -> {destination}") from exc

    def delete(self, path: str, *, missing_ok: bool = False) -> None:
        path = remote_path(path, "delete path")
        try:
            self.ftp.delete(path)
        except ftplib.error_perm as exc:
            if missing_ok and str(exc).startswith("550"):
                return
            raise ValidationError(f"FTP delete failed for {path}") from exc


# Keep the old symbol importable for contract tests and downstream tooling while
# making the transport boundary explicit in the validator implementation.
LegacyFTPTransport = FTPTransport


class CshostAPI:
    def __init__(self, base_url: str, token: str, timeout: int = 30):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValidationError("CSHOST API base URL must be an HTTPS URL without query or fragment")
        self.base_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        self.token = require_text(token, "CSHOST API token")
        self.timeout = timeout

    def call(self, query: str, **parameters: str) -> dict:
        values = {"token": self.token, "query": query, **parameters}
        url = f"{self.base_url}?{urllib.parse.urlencode(values)}"
        request = urllib.request.Request(url, headers={"User-Agent": "cs2-vip-runtime-validation/3"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read(1024 * 1024)
        except Exception as exc:
            raise ValidationError(f"CSHOST API {query} failed: {type(exc).__name__}") from exc
        try:
            result = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError(f"CSHOST API {query} returned invalid JSON") from exc
        if not isinstance(result, dict) or str(result.get("status", "")).lower() != "ok":
            raise ValidationError(f"CSHOST API {query} did not return status=ok")
        return result

    def status(self) -> dict:
        return self.call("status")

    def assert_stage_identity(self, expected_stage_id: str) -> dict:
        """Bind the HTTPS control plane to the hash-pinned runtime sentinel."""
        status = self.status()
        observed = status.get("stage_id", status.get("stageId"))
        if observed != expected_stage_id:
            raise ValidationError("CSHOST API stage identity does not match the sentinel")
        return {"stage_id": expected_stage_id}

    def is_online(self) -> bool:
        value = str(self.status().get("online", ""))
        if value == "1":
            return True
        if value.isdigit() and int(value) >= 2:
            return False
        raise ValidationError("CSHOST status response has an unknown online value")

    def assert_no_players(self) -> dict:
        status = self.status()
        resources = self.call("getresources")
        try:
            resource_players = int(resources["players"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("CSHOST getresources response has no numeric players field") from exc
        status_players = status.get("dataPlayers")
        if status_players is not None and not isinstance(status_players, (list, dict)):
            raise ValidationError("CSHOST status dataPlayers has an unknown shape")
        listed_players = len(status_players) if status_players is not None else 0
        if resource_players != 0 or listed_players != 0:
            raise ValidationError(f"test server has players (resources={resource_players}, listed={listed_players})")
        return {"resources_players": resource_players, "listed_players": listed_players}

    def wait_online(self, expected: bool, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_online() is expected:
                return
            time.sleep(2)
        raise ValidationError(f"CSHOST server did not become {'online' if expected else 'offline'}")

    def start(self, timeout: int) -> None:
        self.call("start")
        self.wait_online(True, timeout)

    def stop(self, timeout: int) -> None:
        self.call("stop")
        self.wait_online(False, timeout)

    def console(self, command: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_. -]+", command):
            raise ValidationError("console command contains forbidden characters")
        self.call("consolecmd", cmd=command)


def _read_cstring(payload: bytes, offset: int) -> tuple[str, int]:
    end = payload.find(b"\0", offset)
    if end < 0:
        raise ValidationError("malformed A2S_INFO string")
    return payload[offset:end].decode("utf-8", errors="replace"), end + 1


def query_a2s_info(host: str, port: int, timeout: float = 3.0) -> dict:
    request = b"\xff\xff\xff\xffTSource Engine Query\x00"
    try:
        resolved = socket.gethostbyname(host)
        address = (resolved, port)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(timeout)
            connection.sendto(request, address)
            payload, responder = connection.recvfrom(65535)
            if responder != address:
                raise ValidationError("A2S response came from an unexpected address")
            if payload[:5] == b"\xff\xff\xff\xffA":
                if len(payload) != 9:
                    raise ValidationError("malformed A2S challenge")
                connection.sendto(request + payload[5:9], address)
                payload, responder = connection.recvfrom(65535)
                if responder != address:
                    raise ValidationError("A2S challenge response came from an unexpected address")
    except (OSError, socket.timeout) as exc:
        raise ValidationError(f"A2S_INFO query failed: {type(exc).__name__}") from exc
    if len(payload) < 6 or payload[:5] != b"\xff\xff\xff\xffI":
        raise ValidationError("unexpected A2S_INFO response")
    offset = 6
    name, offset = _read_cstring(payload, offset)
    game_map, offset = _read_cstring(payload, offset)
    folder, offset = _read_cstring(payload, offset)
    game, offset = _read_cstring(payload, offset)
    if len(payload) < offset + 9:
        raise ValidationError("truncated A2S_INFO response")
    app_id = struct.unpack_from("<H", payload, offset)[0]
    offset += 9
    version, _ = _read_cstring(payload, offset)
    return {"name": name, "map": game_map, "folder": folder, "game": game, "app_id": app_id, "version": version}


def load_candidate(artifact_dir: Path, expected_commit: str) -> dict:
    if not COMMIT_RE.fullmatch(expected_commit):
        raise ValidationError("expected commit must be a lowercase 40-character SHA")
    names = sorted(path.name for path in artifact_dir.iterdir())
    if names != ["vip.spdx.json", "vip.zip"] or any(not path.is_file() for path in artifact_dir.iterdir()):
        raise ValidationError(f"artifact directory must contain exactly vip.zip and vip.spdx.json, got {names}")
    archive_path = artifact_dir / "vip.zip"
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or PLUGIN_PATH not in names:
            raise ValidationError("candidate archive has duplicate entries or no exact VIP binary")
        for entry in entries:
            pure = PurePosixPath(entry.filename)
            if pure.is_absolute() or ".." in pure.parts or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValidationError(f"candidate archive contains unsafe entry: {entry.filename}")
        binary = archive.read(PLUGIN_PATH)
    if expected_commit.encode() not in binary:
        raise ValidationError("candidate binary does not contain the expected VIP_BUILD_COMMIT")
    return {
        "archive_path": archive_path,
        "archive_sha256": sha256_file(archive_path),
        "binary": binary,
        "binary_sha256": sha256_bytes(binary),
    }


def validate_probe(value: dict, nonce: str, expected_commit: str, expected_stage_id: str) -> dict:
    if not isinstance(value, dict) or value.get("schema") != PROBE_SCHEMA or value.get("nonce") != nonce:
        raise ValidationError("runtime probe schema or nonce mismatch")
    if (value.get("build_commit") != expected_commit or value.get("stage_id") != expected_stage_id
            or value.get("ready") is not True):
        raise ValidationError("runtime probe commit/readiness mismatch")
    interfaces = value.get("interfaces")
    if not isinstance(interfaces, dict) or interfaces.get("IVIPApi001") is not True or interfaces.get("IVIPApi002") is not True:
        raise ValidationError("runtime probe did not prove both public VIP interfaces")
    migration = value.get("migration")
    if not isinstance(migration, dict) or migration.get("status") != "ready" or migration.get("account_id_type") != "bigint unsigned":
        raise ValidationError("runtime probe did not prove the final database schema")
    require_text(value.get("version"), "runtime probe version")
    return value


def load_journal(ftp: Transport) -> dict | None:
    journal_path = JOURNAL_PATH if ftp.exists(JOURNAL_PATH) else LEGACY_JOURNAL_PATH
    if not ftp.exists(journal_path):
        return None
    try:
        journal = json.loads(ftp.download(journal_path))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("remote rollback journal is invalid JSON") from exc
    if not isinstance(journal, dict) or journal.get("schema") not in {JOURNAL_SCHEMA, LEGACY_JOURNAL_SCHEMA}:
        raise ValidationError("remote rollback journal schema is invalid")
    if journal.get("plugin_path") != PLUGIN_PATH:
        raise ValidationError("remote rollback journal plugin path is invalid")
    backup = remote_path(journal.get("backup_path"), "journal.backup_path")
    if not backup.startswith(".vip-ci/backups/vip.so."):
        raise ValidationError("remote rollback journal backup path is invalid")
    journal["backup_path"] = backup
    journal["original_sha256"] = require_sha256(journal.get("original_sha256"), "journal.original_sha256")
    journal["candidate_sha256"] = require_sha256(journal.get("candidate_sha256"), "journal.candidate_sha256")
    backup_sha = journal.get("backup_sha256", journal["original_sha256"])
    journal["backup_sha256"] = require_sha256(backup_sha, "journal.backup_sha256")
    journal["journal_path"] = journal_path
    if not isinstance(journal.get("original_online"), bool):
        raise ValidationError("journal.original_online must be boolean")
    return journal


def _download_verified(ftp: Transport, path: str, expected_sha256: str, field: str) -> bytes:
    payload = ftp.download(path)
    actual = sha256_bytes(payload)
    if actual != expected_sha256:
        raise ValidationError(f"{field} SHA-256 mismatch")
    return payload


def restore_from_journal(api: CshostAPI, ftp: Transport, config: dict, journal: dict) -> dict:
    """Restore without deleting the installed binary until backup is verified."""
    if api.is_online():
        api.stop(config["shutdown_timeout_seconds"])
    plugin_exists = ftp.exists(PLUGIN_PATH)
    installed_hash = None
    if plugin_exists:
        installed_hash = sha256_bytes(ftp.download(PLUGIN_PATH))
        if installed_hash not in {journal["original_sha256"], journal["candidate_sha256"]}:
            raise ValidationError("rollback refused: installed VIP binary is neither candidate nor original")

    backup_exists = ftp.exists(journal["backup_path"])
    if installed_hash != journal["original_sha256"]:
        # Verify the backup before moving or deleting the candidate.  This is
        # the critical invariant missing from the previous implementation.
        if not backup_exists:
            raise ValidationError("rollback failed: verified original backup is missing")
        backup_payload = _download_verified(
            ftp, journal["backup_path"], journal["original_sha256"], "rollback backup"
        )
        staging = f"{journal['backup_path']}.restore-{secrets.token_hex(8)}"
        quarantine = f"{PLUGIN_PATH}.quarantine-{secrets.token_hex(8)}"
        ftp.upload_atomic(staging, backup_payload)
        _download_verified(ftp, staging, journal["original_sha256"], "rollback staging")
        if ftp.exists(PLUGIN_PATH):
            ftp.rename(PLUGIN_PATH, quarantine)
        try:
            ftp.rename(staging, PLUGIN_PATH)
            _download_verified(ftp, PLUGIN_PATH, journal["original_sha256"], "restored VIP")
        except Exception:
            # Preserve both quarantine and journal for restore-only recovery.
            if ftp.exists(PLUGIN_PATH):
                ftp.rename(PLUGIN_PATH, staging)
            if ftp.exists(quarantine) and not ftp.exists(PLUGIN_PATH):
                ftp.rename(quarantine, PLUGIN_PATH)
            raise
        ftp.delete(quarantine, missing_ok=True)

    if not ftp.exists(PLUGIN_PATH):
        raise ValidationError("rollback failed: original VIP binary is missing")
    restored_hash = sha256_bytes(ftp.download(PLUGIN_PATH))
    if restored_hash != journal["original_sha256"]:
        raise ValidationError("rollback failed: restored VIP SHA-256 mismatch")
    if journal["original_online"]:
        api.start(config["startup_timeout_seconds"])
    elif api.is_online():
        api.stop(config["shutdown_timeout_seconds"])
    state_restored = api.is_online() is journal["original_online"]
    if not state_restored:
        raise ValidationError("rollback failed: original server state was not restored")
    # Cleanup is deliberately last.  If it fails, the journal remains and the
    # next restore-only run can safely verify the already-restored binary.
    ftp.delete(journal["backup_path"], missing_ok=True)
    ftp.delete(journal.get("journal_path", JOURNAL_PATH), missing_ok=True)
    return {
        "result": "success",
        "restored_binary_sha256": restored_hash,
        "state_restored": state_restored,
        "completed_at": utc_now(),
    }


def add_stage(report: dict, name: str, status: str, **details: object) -> None:
    report.setdefault("stages", []).append({"name": name, "status": status, "at": utc_now(), **details})


def poll_probe(ftp: Transport, path: str, nonce: str, commit: str, stage_id: str, timeout: int) -> dict:
    deadline = time.monotonic() + timeout
    last_error = "evidence file has not appeared"
    while time.monotonic() < deadline:
        if ftp.exists(path):
            try:
                value = json.loads(ftp.download(path))
                return validate_probe(value, nonce, commit, stage_id)
            except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
                last_error = str(exc)
        time.sleep(2)
    raise ValidationError(f"runtime probe timed out: {last_error}")


def run(args: argparse.Namespace, report: dict) -> None:
    if args.transport == "legacy-ftp" and os.environ.get("CSHOST_RUNTIME_NETWORK_PREFLIGHT") != "passed":
        raise ValidationError("plain FTP requires a passed isolated-runner network preflight")
    report["network_preflight"] = {
        "status": "passed",
        "policy_id": args.runner_policy_id,
    }
    api = CshostAPI(args.api_base, args.api_token)
    with LegacyFTPTransport(args.ftp_host, args.ftp_port, args.ftp_user, args.ftp_password, args.ftp_root) as ftp:
        sentinel_raw = ftp.download(SENTINEL_PATH)
        config = load_sentinel(sentinel_raw, args.sentinel_sha256)
        report["stage_id"] = config["stage_id"]
        report["stage_identity"] = api.assert_stage_identity(config["stage_id"])
        add_stage(report, "sentinel", "success", sha256=sha256_bytes(sentinel_raw))
        players = api.assert_no_players()
        add_stage(report, "players-preflight", "success", **players)

        existing = load_journal(ftp)
        if existing is not None:
            report["automatic_recovery"] = restore_from_journal(api, ftp, config, existing)
            add_stage(report, "automatic-recovery", "success")
        if args.mode == "restore-only":
            report["result"] = "success"
            report["rollback"] = report.get("automatic_recovery", {"result": "not-needed", "state_restored": True})
            return

        candidate = load_candidate(args.artifact_dir, args.expected_commit)
        report["artifact"] = {
            "archive_sha256": candidate["archive_sha256"],
            "binary_sha256": candidate["binary_sha256"],
        }
        dependencies = []
        for dependency in config["runtime_dependencies"]:
            if dependency["optional"] and not ftp.exists(dependency["path"]):
                dependencies.append({**dependency, "status": "absent"})
                continue
            actual = sha256_bytes(ftp.download(dependency["path"]))
            if actual != dependency["sha256"]:
                raise ValidationError(f"runtime dependency SHA-256 mismatch: {dependency['name']}")
            dependencies.append({**dependency, "actual_sha256": actual, "status": "verified"})
        report["dependencies"] = dependencies
        add_stage(report, "dependencies", "success", count=len(dependencies))

        original_online = api.is_online()
        players = api.assert_no_players()
        add_stage(report, "players-before-overlay", "success", **players)
        original = ftp.download(PLUGIN_PATH)
        original_sha256 = sha256_bytes(original)
        backup_path = f".vip-ci/backups/vip.so.{int(time.time())}.{original_sha256[:12]}"
        journal = {
            "schema": JOURNAL_SCHEMA,
            "created_at": utc_now(),
            "status": "prepared",
            "plugin_path": PLUGIN_PATH,
            "backup_path": backup_path,
            "original_sha256": original_sha256,
            "backup_sha256": original_sha256,
            "candidate_sha256": candidate["binary_sha256"],
            "original_online": original_online,
            "state": "prepared",
        }
        ftp.upload_json(JOURNAL_PATH, journal)
        add_stage(report, "journal", "success")
        evidence_path = f"{EVIDENCE_DIRECTORY}/vip-runtime-validation-{report['nonce']}.json"
        try:
            if original_online:
                api.stop(config["shutdown_timeout_seconds"])
            add_stage(report, "stop-original", "success", originally_online=original_online)
            ftp.rename(PLUGIN_PATH, backup_path)
            _download_verified(ftp, backup_path, original_sha256, "uploaded original backup")
            journal["status"] = "backed-up"
            journal["state"] = "backed-up"
            ftp.upload_json(JOURNAL_PATH, journal)
            add_stage(report, "backup-original", "success", original_sha256=original_sha256)
            ftp.upload_atomic(PLUGIN_PATH, candidate["binary"])
            if sha256_bytes(ftp.download(PLUGIN_PATH)) != candidate["binary_sha256"]:
                raise ValidationError("candidate binary SHA-256 mismatch after installation")
            journal["status"] = "candidate-installed"
            journal["state"] = "candidate-installed"
            ftp.upload_json(JOURNAL_PATH, journal)
            add_stage(report, "install-candidate", "success")
            api.start(config["startup_timeout_seconds"])
            add_stage(report, "start-candidate", "success")
            a2s = query_a2s_info(config["a2s"]["host"], config["a2s"]["port"])
            if a2s["app_id"] != 730:
                raise ValidationError(f"A2S application ID mismatch: {a2s['app_id']}")
            report["a2s"] = a2s
            report["cs2_build"] = a2s["version"]
            add_stage(report, "a2s", "success", version=a2s["version"])
            ftp.delete(evidence_path, missing_ok=True)
            api.console(f"vip_runtime_probe {report['nonce']} {config['stage_id']}")
            report["probe"] = poll_probe(
                ftp, evidence_path, report["nonce"], args.expected_commit, config["stage_id"],
                config["probe_timeout_seconds"]
            )
            add_stage(report, "runtime-probe", "success")
            report["result"] = "success"
        finally:
            try:
                current_journal = load_journal(ftp)
                if current_journal is None:
                    raise ValidationError("rollback journal disappeared before restoration")
                report["rollback"] = restore_from_journal(api, ftp, config, current_journal)
                add_stage(report, "rollback", "success")
            except Exception as rollback_error:
                report["rollback"] = {
                    "result": "failure",
                    "state_restored": False,
                    "error": f"{type(rollback_error).__name__}: {rollback_error}",
                }
                add_stage(report, "rollback", "failure")
                raise
            finally:
                ftp.delete(evidence_path, missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("validate", "restore-only"), default="validate")
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--build-run-id")
    parser.add_argument("--validation-run-id", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--api-token", required=True)
    parser.add_argument("--ftp-host", required=True)
    parser.add_argument("--ftp-port", type=int, default=21)
    parser.add_argument("--ftp-user", required=True)
    parser.add_argument("--ftp-password", required=True)
    parser.add_argument("--ftp-root", default=".")
    parser.add_argument("--sentinel-sha256", required=True)
    parser.add_argument("--transport", choices=("legacy-ftp",), default="legacy-ftp")
    parser.add_argument("--runner-policy-id", default="cshost-runtime-ephemeral-v1")
    parser.add_argument("--runner-name", default="unknown")
    args = parser.parse_args()
    if not args.validation_run_id.isdigit():
        parser.error("--validation-run-id must be numeric")
    if args.mode == "validate":
        if args.artifact_dir is None or not args.artifact_dir.is_dir():
            parser.error("--artifact-dir is required in validate mode")
        if not args.expected_commit or not COMMIT_RE.fullmatch(args.expected_commit):
            parser.error("--expected-commit must be a lowercase 40-character SHA")
        if not args.build_run_id or not args.build_run_id.isdigit():
            parser.error("--build-run-id must be numeric")
    return args


def main() -> int:
    args = parse_args()
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now(),
        "repository": args.repository,
        "commit": args.expected_commit,
        "build_run_id": args.build_run_id,
        "validation_run_id": args.validation_run_id,
        "nonce": secrets.token_hex(16),
        "result": "failure",
        "artifact": {},
        "dependencies": [],
        "a2s": {},
        "probe": {},
        "rollback": {"result": "not-started", "state_restored": False},
        "transport": args.transport,
        "runner_policy_id": args.runner_policy_id,
        "runner_name": args.runner_name,
        "network_preflight": {"status": "not-run"},
        "stages": [],
    }
    status = 1
    try:
        run(args, report)
        if report["result"] != "success":
            raise ValidationError("validation finished without result=success")
        if report["rollback"].get("result") not in {"success", "not-needed"}:
            raise ValidationError("validation finished without successful rollback")
        status = 0
    except Exception as exc:
        report["result"] = "failure"
        report["error"] = f"{type(exc).__name__}: {exc}"
        print(f"runtime validation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
    finally:
        report["completed_at"] = utc_now()
        write_json_atomic(args.report, report)
        print(f"runtime report: {args.report}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
