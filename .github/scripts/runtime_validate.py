#!/usr/bin/env python3
"""Validate an attested VIP Core candidate on a marked disposable CS2 server."""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import zipfile

from verify_spdx_subject import load_release_package, release_sha256


SENTINEL = ".vip-ci-test-server"
REPORT_SCHEMA = "https://github.com/bywinsty/cs2-vip/runtime-validation-v2"
JOURNAL_SCHEMA = "https://github.com/bywinsty/cs2-vip/runtime-overlay-journal-v1"
SPDX_PREDICATE = "https://spdx.dev/Document/v2.3"
RELEASE_FILES = frozenset({"vip.zip", "vip.spdx.json"})
FORBIDDEN_LOG_PATTERNS = (
    "segmentation fault",
    "unresolved symbol",
    "undefined symbol",
    "interface mismatch",
    "failed to load plugin",
    "load error",
    "fatal error",
)
PLACEHOLDER_RE = re.compile(r"(?:placeholder|replace[-_ ]?me|example|todo|noassertion)", re.IGNORECASE)
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
SIGTERM = getattr(signal, "SIGTERM", 15)
SIGKILL = getattr(signal, "SIGKILL", 9)


class ValidationError(RuntimeError):
    """An expected fail-closed validation error."""


class RuntimeExecutionError(ValidationError):
    """Runtime validation failed, possibly together with shutdown."""

    def __init__(self, message: str, shutdown: dict | None = None):
        super().__init__(message)
        self.shutdown = shutdown


def utc_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_link_like(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path.stat(follow_symlinks=False), "st_reparse_tag", 0))


def _relative_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValidationError(f"{field} must be a non-empty POSIX relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or pure.parts in {(), (".",)} or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValidationError(f"{field} must stay below the server root")
    return pure.as_posix()


def safe_child(root: Path, relative: str, *, reject_links: bool = True) -> Path:
    relative = _relative_path(relative, "path")
    unresolved = root.joinpath(*PurePosixPath(relative).parts)
    if reject_links:
        current = root
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.exists() or current.is_symlink():
                try:
                    if is_link_like(current):
                        raise ValidationError(f"link-like server path is forbidden: {relative}")
                except OSError as exc:
                    raise ValidationError(f"cannot inspect server path {relative}: {exc}") from exc
    try:
        unresolved.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"path escapes marked server root: {relative}") from exc
    return unresolved


def _require_int(config: dict, name: str, *, minimum: int = 1, maximum: int | None = None) -> int:
    value = config.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError(f"sentinel {name} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValidationError(f"sentinel {name} must be <= {maximum}")
    return value


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or PLACEHOLDER_RE.search(value):
        raise ValidationError(f"{field} must be a non-placeholder string")
    return value.strip()


def load_sentinel(server_root: Path) -> dict:
    sentinel = server_root / SENTINEL
    if not sentinel.is_file() or is_link_like(sentinel):
        raise ValidationError(f"refusing to run without regular sentinel file {sentinel}")
    try:
        config = json.loads(sentinel.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid sentinel JSON: {exc}") from exc
    if not isinstance(config, dict):
        raise ValidationError("sentinel must be a JSON object")
    if config.get("schema_version") != 2:
        raise ValidationError("sentinel schema_version must be 2; the legacy runtime contract is rejected")
    if config.get("purpose") != "vip-ci-test-server" or config.get("production") is not False:
        raise ValidationError("sentinel must declare purpose=vip-ci-test-server and production=false")

    config["expected_server_build_id"] = _require_int(config, "expected_server_build_id")
    config["map"] = _require_text(config.get("map"), "sentinel map")
    config["game_directory"] = _relative_path(config.get("game_directory"), "game_directory")
    config["server_build_id_file"] = _relative_path(
        config.get("server_build_id_file"), "server_build_id_file"
    )
    command = config.get("server_command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise ValidationError("sentinel server_command must be a non-empty string array")
    command[0] = _relative_path(command[0], "server_command[0]")
    config["startup_timeout_seconds"] = _require_int(config, "startup_timeout_seconds", maximum=3600)
    config["shutdown_timeout_seconds"] = _require_int(config, "shutdown_timeout_seconds", maximum=300)
    config["minimum_free_gib"] = _require_int(config, "minimum_free_gib", minimum=0, maximum=1024)

    a2s = config.get("a2s")
    if not isinstance(a2s, dict):
        raise ValidationError("sentinel a2s must be an object")
    a2s["host"] = _require_text(a2s.get("host"), "a2s.host")
    a2s["port"] = _require_int(a2s, "port", maximum=65535)
    timeout = a2s.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
        raise ValidationError("a2s.timeout_seconds must be a number in (0, 30]")

    dependencies = config.get("runtime_dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValidationError("sentinel runtime_dependencies must be a non-empty array")
    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    metamod_count = 0
    for index, dependency in enumerate(dependencies):
        field = f"runtime_dependencies[{index}]"
        if not isinstance(dependency, dict):
            raise ValidationError(f"{field} must be an object")
        kind = dependency.get("kind")
        if kind not in {"metamod", "plugin"}:
            raise ValidationError(f"{field}.kind must be metamod or plugin")
        name = _require_text(dependency.get("name"), f"{field}.name")
        version = _require_text(dependency.get("version"), f"{field}.version")
        path = _relative_path(dependency.get("path"), f"{field}.path")
        digest = dependency.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or len(set(digest.lower())) == 1:
            raise ValidationError(f"{field}.sha256 must be a non-placeholder 64-character SHA-256")
        identity = name.casefold()
        if identity in seen_names or path.casefold() in seen_paths:
            raise ValidationError("runtime dependency names and paths must be unique")
        seen_names.add(identity)
        seen_paths.add(path.casefold())
        dependency.update(name=name, path=path, version=version, sha256=digest.lower())
        if kind == "metamod":
            metamod_count += 1
        else:
            dependency["metamod_name"] = _require_text(
                dependency.get("metamod_name"), f"{field}.metamod_name"
            )
    if metamod_count != 1:
        raise ValidationError("runtime_dependencies must contain exactly one Metamod dependency")

    additional = config.get("additional_arguments", [])
    if not isinstance(additional, list) or not all(isinstance(item, str) for item in additional):
        raise ValidationError("additional_arguments must be a string array")
    return config


def running_server_processes(server_binary: Path) -> list[str]:
    if not Path("/proc").is_dir():
        return []
    current = {os.getpid(), os.getppid()}
    matches: list[str] = []
    binary = str(server_binary.resolve())
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) in current:
            continue
        try:
            command = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except (OSError, PermissionError):
            continue
        if binary in command:
            matches.append(f"pid={entry.name} {command.strip()}")
    return matches


def preflight(server_root: Path, config: dict) -> dict:
    if platform.system() != "Linux":
        raise ValidationError("runtime validation is supported only on Linux")
    game_dir = safe_child(server_root, config["game_directory"])
    if not game_dir.is_dir() or is_link_like(game_dir):
        raise ValidationError(f"CS2 game directory is missing or link-like: {game_dir}")
    server_binary = safe_child(server_root, config["server_command"][0])
    if not server_binary.is_file() or is_link_like(server_binary) or not os.access(server_binary, os.X_OK):
        raise ValidationError(f"CS2 dedicated server binary is missing, linked, or not executable: {server_binary}")
    running = running_server_processes(server_binary)
    if running:
        raise ValidationError("a server process is already running: " + "; ".join(running))

    build_file = safe_child(server_root, config["server_build_id_file"])
    if not build_file.is_file() or is_link_like(build_file):
        raise ValidationError(f"server build ID file is missing or link-like: {build_file}")
    try:
        build_text = build_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(f"cannot read server build ID: {exc}") from exc
    match = re.search(r'"buildid"\s+"([0-9]+)"', build_text, flags=re.IGNORECASE)
    if not match:
        raise ValidationError("server build ID file does not contain a numeric buildid")
    actual_build_id = int(match.group(1))
    if actual_build_id != config["expected_server_build_id"]:
        raise ValidationError(
            f"server build ID mismatch: expected {config['expected_server_build_id']}, got {actual_build_id}"
        )

    dependency_results = []
    for dependency in config["runtime_dependencies"]:
        path = safe_child(server_root, dependency["path"])
        if not path.is_file() or is_link_like(path):
            raise ValidationError(f"runtime dependency is missing or link-like: {dependency['name']} ({path})")
        actual_digest = sha256(path)
        if actual_digest != dependency["sha256"]:
            raise ValidationError(
                f"runtime dependency SHA-256 mismatch for {dependency['name']}: "
                f"expected {dependency['sha256']}, got {actual_digest}"
            )
        dependency_results.append({**dependency, "path": path.relative_to(server_root).as_posix()})

    free_bytes = shutil.disk_usage(server_root).free
    required = config["minimum_free_gib"] * 1024**3
    if free_bytes < required:
        raise ValidationError(f"insufficient free space: {free_bytes / 1024**3:.2f} GiB")
    return {
        "game_directory": game_dir,
        "server_binary": server_binary,
        "server_command": config["server_command"],
        "dependencies": dependency_results,
        "server_build_id": actual_build_id,
        "free_bytes": free_bytes,
    }


def run_checked(command: list[str], *, cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
        )
    except OSError as exc:
        raise ValidationError(f"cannot execute {command[0]}: {exc}") from exc
    if result.returncode:
        raise ValidationError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result.stdout


def run_json(command: list[str]) -> dict:
    output = run_checked(command)
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"command returned malformed JSON: {' '.join(command)}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"command did not return a JSON object: {' '.join(command)}")
    return value


def verify_attestations(archive: Path, sbom: Path, repository: str) -> None:
    common = ["--repo", repository]
    run_checked(["gh", "attestation", "verify", str(archive), *common])
    run_checked(
        ["gh", "attestation", "verify", str(archive), *common, "--predicate-type", SPDX_PREDICATE]
    )
    run_checked(["gh", "attestation", "verify", str(sbom), *common])


def verify_subjects(artifact_dir: Path, repository: str, expected_commit: str) -> tuple[Path, Path, dict]:
    try:
        entries = list(artifact_dir.iterdir())
        names = {path.name for path in entries if path.is_file()}
    except OSError as exc:
        raise ValidationError(f"cannot inspect artifact directory: {exc}") from exc
    if names != RELEASE_FILES or len(entries) != len(RELEASE_FILES):
        raise ValidationError(f"artifact must contain exactly {sorted(RELEASE_FILES)}, got {sorted(names)}")
    archive = artifact_dir / "vip.zip"
    sbom = artifact_dir / "vip.spdx.json"
    if is_link_like(archive) or is_link_like(sbom):
        raise ValidationError("release subjects must be regular non-link files")
    try:
        package = load_release_package(sbom, archive.name)
        subject_digest = release_sha256(package)
    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError, TypeError, ValueError) as exc:
        raise ValidationError(f"invalid SPDX release subject: {exc}") from exc
    if package.get("versionInfo") != expected_commit:
        raise ValidationError(
            f"SPDX commit mismatch: expected {expected_commit}, got {package.get('versionInfo')!r}"
        )
    archive_digest = sha256(archive)
    if subject_digest != archive_digest:
        raise ValidationError(f"SPDX archive digest mismatch: expected {subject_digest}, got {archive_digest}")
    verify_attestations(archive, sbom, repository)
    return archive, sbom, {
        "commit": expected_commit,
        "archive_sha256": archive_digest,
        "archive_size": archive.stat().st_size,
        "sbom_sha256": sha256(sbom),
        "sbom_size": sbom.stat().st_size,
        "attestations": ["zip-provenance", "zip-spdx", "spdx-provenance"],
    }


def acquire_artifacts(args: argparse.Namespace, destination: Path) -> dict:
    if args.artifact_dir is not None:
        source = args.artifact_dir.resolve()
        try:
            source_entries = list(source.iterdir())
        except OSError as exc:
            raise ValidationError(f"cannot inspect local artifact directory: {exc}") from exc
        if {path.name for path in source_entries} != RELEASE_FILES or not all(
            path.is_file() and not is_link_like(path) for path in source_entries
        ):
            raise ValidationError(f"local artifact directory must contain exactly {sorted(RELEASE_FILES)}")
        for name in RELEASE_FILES:
            path = source / name
            shutil.copy2(path, destination / name)
        return {"source": "artifact-dir", "path": str(source)}

    if args.run_id is not None:
        metadata = run_json(
            [
                "gh", "run", "view", str(args.run_id), "--repo", args.repository,
                "--json", "databaseId,headSha,headBranch,event,conclusion",
            ]
        )
        if metadata.get("databaseId") != args.run_id:
            raise ValidationError("GitHub returned metadata for a different run")
        if metadata.get("headSha") != args.expected_commit:
            raise ValidationError("candidate run headSha does not match --expected-commit")
        if metadata.get("headBranch") not in {"PR", "Core"}:
            raise ValidationError("candidate run must belong to PR or Core")
        if metadata.get("event") != "push" or metadata.get("conclusion") != "success":
            raise ValidationError("candidate run must be a successful push workflow run")
        run_checked(
            [
                "gh", "run", "download", str(args.run_id), "--repo", args.repository,
                "--name", "compile", "--dir", str(destination),
            ]
        )
        return {"source": "run-id", "run_id": args.run_id, **metadata}

    tag_sha = run_checked(
        ["gh", "api", f"repos/{args.repository}/git/ref/tags/{args.tag}", "--jq", ".object.sha"]
    ).strip()
    if tag_sha != args.expected_commit:
        raise ValidationError(f"release tag {args.tag} points to {tag_sha}, expected {args.expected_commit}")
    run_checked(
        [
            "gh", "release", "download", args.tag, "--repo", args.repository,
            "--pattern", "vip.zip", "--pattern", "vip.spdx.json", "--dir", str(destination),
        ]
    )
    return {"source": "tag", "tag": args.tag, "commit": tag_sha}


def extract_zip_safely(archive: Path, destination: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as handle:
            seen: set[str] = set()
            for item in handle.infolist():
                name = item.filename
                canonical = name[:-1] if item.is_dir() and name.endswith("/") else name
                raw_parts = canonical.split("/")
                pure = PurePosixPath(canonical)
                if (
                    not canonical or "\\" in name or re.match(r"^[A-Za-z]:", canonical) or
                    pure.is_absolute() or any(part in {"", ".", ".."} for part in raw_parts) or
                    canonical in seen
                ):
                    raise ValidationError(f"unsafe or duplicate archive member: {name!r}")
                seen.add(canonical)
                mode = item.external_attr >> 16
                file_type = mode & 0o170000
                if file_type not in {0, 0o040000, 0o100000}:
                    raise ValidationError(f"archive links or special files are forbidden: {name}")
            handle.extractall(destination)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValidationError(f"invalid release ZIP: {exc}") from exc


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def write_json_atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _overlay_files(source: Path) -> tuple[list[Path], list[Path]]:
    directories: list[Path] = []
    files: list[Path] = []
    for path in sorted(source.rglob("*")):
        if is_link_like(path):
            raise ValidationError(f"overlay contains a link-like path: {path}")
        if path.is_dir():
            directories.append(path)
        elif path.is_file():
            files.append(path)
        else:
            raise ValidationError(f"overlay contains a non-regular path: {path}")
    return directories, files


def create_overlay_journal(source: Path, target: Path, report_dir: Path) -> Path:
    journal_path = report_dir / "overlay-journal.json"
    if journal_path.exists() or journal_path.is_symlink():
        raise ValidationError(f"refusing to overwrite existing rollback journal: {journal_path}")
    backup_root = Path(tempfile.mkdtemp(prefix="rollback-backup-", dir=report_dir))
    directories, files = _overlay_files(source)
    journal: dict = {
        "schema": JOURNAL_SCHEMA,
        "created_at": utc_now(),
        "status": "installing",
        "target_root": str(target.resolve()),
        "backup_root": str(backup_root.resolve()),
        "created_directories": [],
        "entries": [],
    }
    write_json_atomic(journal_path, journal)
    try:
        for directory in directories:
            relative = directory.relative_to(source).as_posix()
            destination = safe_child(target, relative)
            if not destination.exists():
                journal["created_directories"].append(relative)
                write_json_atomic(journal_path, journal)
                destination.mkdir()
            elif not destination.is_dir() or is_link_like(destination):
                raise ValidationError(f"refusing to overlay non-directory path: {destination}")

        for candidate in files:
            relative = candidate.relative_to(source).as_posix()
            destination = safe_child(target, relative)
            existed = destination.exists() or destination.is_symlink()
            original_digest = None
            backup_relative = None
            if existed:
                if not destination.is_file() or is_link_like(destination):
                    raise ValidationError(f"refusing to replace non-regular server path: {destination}")
                original_digest = sha256(destination)
                backup_relative = relative
                backup = safe_child(backup_root, relative)
                atomic_copy(destination, backup)
            entry = {
                "relative_path": relative,
                "existed_before": existed,
                "original_sha256": original_digest,
                "candidate_sha256": sha256(candidate),
                "backup_path": backup_relative,
                "installed": False,
            }
            journal["entries"].append(entry)
            write_json_atomic(journal_path, journal)
            atomic_copy(candidate, destination)
            if sha256(destination) != entry["candidate_sha256"]:
                raise ValidationError(f"installed overlay hash mismatch: {relative}")
            entry["installed"] = True
            write_json_atomic(journal_path, journal)
        journal["status"] = "installed"
        write_json_atomic(journal_path, journal)
        return journal_path
    except Exception:
        journal["status"] = "install-failed"
        write_json_atomic(journal_path, journal)
        raise


def load_journal(journal_path: Path) -> dict:
    if not journal_path.is_file() or is_link_like(journal_path):
        raise ValidationError(f"rollback journal must be a regular file: {journal_path}")
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid rollback journal: {exc}") from exc
    if not isinstance(journal, dict) or journal.get("schema") != JOURNAL_SCHEMA:
        raise ValidationError("unsupported rollback journal schema")
    if not isinstance(journal.get("entries"), list) or not isinstance(journal.get("created_directories"), list):
        raise ValidationError("malformed rollback journal collections")
    return journal


def restore_overlay(journal_path: Path, *, cleanup: bool = False) -> dict:
    journal = load_journal(journal_path)
    journal_path = journal_path.resolve(strict=True)
    target = Path(journal.get("target_root", "")).resolve(strict=True)
    backup_root = Path(journal.get("backup_root", "")).resolve(strict=False)
    try:
        backup_root.relative_to(journal_path.parent.resolve())
    except ValueError as exc:
        raise ValidationError("rollback backup must remain below the report directory") from exc
    restored: list[dict] = []
    try:
        for entry in reversed(journal["entries"]):
            if not isinstance(entry, dict):
                raise ValidationError("malformed rollback journal entry")
            relative = _relative_path(entry.get("relative_path"), "journal relative_path")
            destination = safe_child(target, relative)
            expected_candidate = entry.get("candidate_sha256")
            if not isinstance(expected_candidate, str) or not SHA256_RE.fullmatch(expected_candidate):
                raise ValidationError(f"malformed candidate digest in journal: {relative}")
            if entry.get("existed_before") is True:
                expected_original = entry.get("original_sha256")
                backup_relative = _relative_path(entry.get("backup_path"), "journal backup_path")
                backup = safe_child(backup_root, backup_relative)
                if destination.is_file() and not is_link_like(destination) and sha256(destination) == expected_original:
                    restored.append({"path": relative, "state": "already-restored"})
                    continue
                if not backup.is_file() or is_link_like(backup):
                    raise ValidationError(f"rollback backup is missing or linked: {relative}")
                if sha256(backup) != expected_original:
                    raise ValidationError(f"rollback backup hash mismatch: {relative}")
                if destination.exists() and (not destination.is_file() or is_link_like(destination)):
                    raise ValidationError(f"rollback destination is not a regular file: {relative}")
                if destination.is_file() and sha256(destination) != expected_candidate:
                    raise ValidationError(f"overlay destination changed after installation: {relative}")
                atomic_copy(backup, destination)
                if sha256(destination) != expected_original:
                    raise ValidationError(f"rollback verification failed: {relative}")
                restored.append({"path": relative, "state": "restored"})
            elif entry.get("existed_before") is False:
                if not destination.exists() and not destination.is_symlink():
                    restored.append({"path": relative, "state": "already-absent"})
                    continue
                if not destination.is_file() or is_link_like(destination):
                    raise ValidationError(f"new overlay destination changed type: {relative}")
                if sha256(destination) != expected_candidate:
                    raise ValidationError(f"new overlay file changed after installation: {relative}")
                destination.unlink()
                if destination.exists() or destination.is_symlink():
                    raise ValidationError(f"could not remove new overlay file: {relative}")
                restored.append({"path": relative, "state": "removed"})
            else:
                raise ValidationError(f"malformed existed_before value: {relative}")

        for relative in sorted(journal["created_directories"], key=lambda item: len(PurePosixPath(item).parts), reverse=True):
            directory = safe_child(target, _relative_path(relative, "created directory"))
            if directory.exists():
                if not directory.is_dir() or is_link_like(directory):
                    raise ValidationError(f"created overlay directory changed type: {relative}")
                try:
                    directory.rmdir()
                except OSError as exc:
                    if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
                        raise
        journal["status"] = "restored"
        journal["restored_at"] = utc_now()
        write_json_atomic(journal_path, journal)
    except (OSError, ValidationError) as exc:
        journal["status"] = "restore-failed"
        journal["restore_error"] = str(exc)
        write_json_atomic(journal_path, journal)
        raise ValidationError(f"rollback failed; journal and backup preserved: {exc}") from exc

    result = {"status": "restored", "journal": str(journal_path), "files": restored}
    if cleanup:
        if backup_root.exists():
            shutil.rmtree(backup_root)
        journal_path.unlink(missing_ok=True)
        result["cleanup"] = "complete"
    return result


def restore_overlay_with_retry(journal_path: Path, *, attempts: int = 2) -> dict:
    errors: list[str] = []
    for attempt in range(1, attempts + 1):
        try:
            result = restore_overlay(journal_path, cleanup=True)
            result["attempts"] = attempt
            result["previous_errors"] = errors
            return result
        except ValidationError as exc:
            errors.append(str(exc))
    raise ValidationError(
        f"rollback failed after {attempts} attempts; journal and backup preserved: {errors[-1]}"
    )


def _read_cstring(payload: bytes, offset: int) -> tuple[str, int]:
    end = payload.find(b"\0", offset)
    if end < 0:
        raise ValidationError("malformed A2S_INFO string")
    return payload[offset:end].decode("utf-8", errors="replace"), end + 1


def parse_a2s_info_payload(payload: bytes) -> dict:
    if len(payload) < 6 or payload[:4] != b"\xff\xff\xff\xff" or payload[4:5] != b"I":
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


def query_a2s_info(host: str, port: int, timeout: float) -> dict:
    request = b"\xff\xff\xff\xffTSource Engine Query\x00"
    try:
        resolved_host = socket.gethostbyname(host)
        address = (resolved_host, port)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(timeout)
            connection.sendto(request, address)
            payload, responder = connection.recvfrom(65535)
            if responder != address:
                raise ValidationError(f"A2S response came from unexpected server: {responder}")
            if payload[:5] == b"\xff\xff\xff\xffA":
                if len(payload) != 9:
                    raise ValidationError("malformed A2S challenge response")
                connection.sendto(request + payload[5:9], address)
                payload, responder = connection.recvfrom(65535)
                if responder != address:
                    raise ValidationError(f"A2S response came from unexpected server: {responder}")
    except (OSError, socket.timeout) as exc:
        raise ValidationError(f"A2S_INFO query failed: {exc}") from exc
    return parse_a2s_info_payload(payload)


def parse_runtime_evidence(log_text: str, nonce: str, config: dict) -> dict:
    lowered = log_text.lower()
    found_forbidden = [marker for marker in FORBIDDEN_LOG_PATTERNS if marker in lowered]
    if found_forbidden:
        raise ValidationError(f"forbidden runtime log markers: {found_forbidden}")
    events: dict[str, dict] = {}
    marker = "[VIP-CI] "
    for line in log_text.splitlines():
        if marker not in line:
            continue
        raw = line.split(marker, 1)[1].strip()
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"malformed VIP runtime evidence JSON: {exc}") from exc
        if not isinstance(event, dict) or event.get("nonce") != nonce:
            raise ValidationError("VIP runtime evidence has an invalid nonce or shape")
        name = event.get("event")
        if name not in {"interfaces", "core_ready"}:
            raise ValidationError(f"unknown VIP runtime evidence event: {name!r}")
        if name in events:
            raise ValidationError(f"duplicate VIP runtime evidence event: {name}")
        events[name] = event

    interfaces = events.get("interfaces")
    ready = events.get("core_ready")
    if interfaces is None or interfaces.get("legacy") is not True or interfaces.get("v2") is not True:
        raise ValidationError("successful IVIPApi and IVIPApi002 evidence is missing")
    if ready is None or ready.get("ready") is not True:
        raise ValidationError("core_ready evidence is missing")
    version = _require_text(ready.get("version"), "core_ready.version")

    dependency_evidence = []
    for dependency in config["runtime_dependencies"]:
        identity = dependency["name"] if dependency["kind"] == "metamod" else dependency["metamod_name"]
        matches = [line for line in log_text.splitlines() if identity in line and dependency["version"] in line]
        if not matches:
            raise ValidationError(
                f"runtime version evidence missing for {dependency['name']} {dependency['version']}"
            )
        dependency_evidence.append(
            {"kind": dependency["kind"], "name": dependency["name"], "version": dependency["version"]}
        )
    return {"interfaces": interfaces, "core_ready": {**ready, "version": version}, "dependencies": dependency_evidence}


def terminate_process_group(process: subprocess.Popen, timeout: int) -> dict:
    if process.poll() is not None:
        return {"status": "already-exited", "returncode": process.returncode}
    try:
        os.killpg(process.pid, SIGTERM)
    except ProcessLookupError:
        return {"status": "already-exited", "returncode": process.poll()}
    try:
        returncode = process.wait(timeout=timeout)
        return {"status": "terminated", "signal": "SIGTERM", "returncode": returncode}
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, SIGKILL)
    except ProcessLookupError:
        return {"status": "exited-before-kill", "returncode": process.poll()}
    try:
        returncode = process.wait(timeout=max(1, min(timeout, 10)))
    except subprocess.TimeoutExpired as exc:
        raise ValidationError("server process group did not stop after SIGKILL") from exc
    return {"status": "killed", "signal": "SIGKILL", "returncode": returncode}


def launch_and_validate(
    server_root: Path, config: dict, preflight_result: dict, log_path: Path
) -> tuple[dict, dict, dict]:
    nonce = secrets.token_hex(16)
    command = [str(preflight_result["server_binary"]), *preflight_result["server_command"][1:]]
    command.extend(["-dedicated", "-insecure", "-usercon", "+sv_lan", "1", "+map", config["map"]])
    command.extend(["+meta", "version", "+meta", "list"])
    command.extend(config.get("additional_arguments", []))
    environment = os.environ.copy()
    environment.update(VIP_CI_RUNTIME_PROBE="1", VIP_CI_RUNTIME_NONCE=nonce)
    runtime: dict | None = None
    evidence: dict | None = None
    failure: Exception | None = None
    shutdown: dict | None = None
    with log_path.open("w", encoding="utf-8", newline="\n") as log_handle:
        process = subprocess.Popen(
            command,
            cwd=server_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        deadline = time.monotonic() + config["startup_timeout_seconds"]
        last_error = "runtime evidence has not appeared"
        try:
            while time.monotonic() < deadline:
                log_handle.flush()
                text = log_path.read_text(encoding="utf-8", errors="replace")
                try:
                    evidence = parse_runtime_evidence(text, nonce, config)
                    a2s = query_a2s_info(
                        config["a2s"]["host"], config["a2s"]["port"], config["a2s"]["timeout_seconds"]
                    )
                    if a2s["map"] != config["map"]:
                        raise ValidationError(f"A2S map mismatch: expected {config['map']}, got {a2s['map']}")
                    if process.poll() is not None:
                        raise ValidationError(f"server exited after readiness evidence: {process.returncode}")
                    runtime = {"command": command, "map": config["map"], "a2s": a2s}
                    break
                except ValidationError as exc:
                    last_error = str(exc)
                    if any(marker in text.lower() for marker in FORBIDDEN_LOG_PATTERNS):
                        raise
                if process.poll() is not None:
                    raise ValidationError(f"server exited before readiness: {process.returncode}; {last_error}")
                time.sleep(1)
            if runtime is None or evidence is None:
                raise ValidationError(
                    f"runtime validation timed out after {config['startup_timeout_seconds']}s: {last_error}"
                )
        except Exception as exc:
            failure = exc
        finally:
            try:
                shutdown = terminate_process_group(process, config["shutdown_timeout_seconds"])
            except ValidationError as exc:
                shutdown = {"status": "failed", "error": str(exc)}
                if failure is None:
                    failure = exc
    if failure is not None:
        raise RuntimeExecutionError(str(failure), shutdown) from failure
    assert runtime is not None and evidence is not None and shutdown is not None
    if shutdown.get("status") == "failed":
        raise RuntimeExecutionError("server shutdown failed", shutdown)
    return runtime, shutdown, evidence


def write_log_archive(log_directory: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in log_directory.rglob("*") if item.is_file()):
            archive.write(path, path.relative_to(log_directory).as_posix())


def serializable_preflight(value: dict) -> dict:
    return {key: str(item) if isinstance(item, Path) else item for key, item in value.items()}


def validate_report_location(server_root: Path, report_dir: Path) -> None:
    try:
        report_dir.resolve(strict=False).relative_to(server_root.resolve(strict=True))
    except ValueError:
        return
    raise ValidationError("report-dir must be outside the disposable server root")


def run_validation(args: argparse.Namespace, report: dict, log_dir: Path) -> int:
    server_root = Path(args.server_root).resolve(strict=True)
    validate_report_location(server_root, args.report_dir)
    config = load_sentinel(server_root)
    preflight_result = preflight(server_root, config)
    report["preflight"] = serializable_preflight(preflight_result)
    report["preflight"]["expected_server_build_id"] = config["expected_server_build_id"]
    if args.preflight_only:
        report["result"] = "success"
        return 0

    journal_path: Path | None = None
    artifact_temp = Path(tempfile.mkdtemp(prefix="vip-runtime-artifacts-"))
    overlay_temp = Path(tempfile.mkdtemp(prefix="vip-runtime-overlay-"))
    try:
        report["artifact"] = acquire_artifacts(args, artifact_temp)
        archive, _sbom, subjects = verify_subjects(
            artifact_temp, args.repository, args.expected_commit
        )
        report["artifact"].update(subjects)
        extract_zip_safely(archive, overlay_temp)
        candidate_journal = args.report_dir / "overlay-journal.json"
        if candidate_journal.exists() or candidate_journal.is_symlink():
            raise ValidationError(f"refusing to overwrite existing rollback journal: {candidate_journal}")
        journal_path = candidate_journal
        create_overlay_journal(overlay_temp, preflight_result["game_directory"], args.report_dir)
        try:
            runtime, shutdown, evidence = launch_and_validate(
                server_root, config, preflight_result, log_dir / "cs2-server.log"
            )
            report["runtime"] = runtime
            report["shutdown"] = shutdown
            report["evidence"] = evidence
        except RuntimeExecutionError as exc:
            if exc.shutdown is not None:
                report["shutdown"] = exc.shutdown
            raise
        report["rollback"] = restore_overlay_with_retry(journal_path)
        journal_path = None
        report["result"] = "success"
        return 0
    finally:
        if journal_path is not None and journal_path.exists():
            try:
                report["rollback"] = restore_overlay_with_retry(journal_path)
                journal_path = None
            except ValidationError as exc:
                report["rollback"] = {
                    "status": "failed",
                    "error": str(exc),
                    "journal": str(journal_path),
                }
        shutil.rmtree(artifact_temp, ignore_errors=True)
        shutil.rmtree(overlay_temp, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-root", default=os.environ.get("CS2_SERVER_ROOT"))
    parser.add_argument("--repository", default="bywinsty/cs2-vip")
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument("--run-id", type=int)
    sources.add_argument("--tag", choices=("dev", "Core"))
    sources.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--report-dir", type=Path, default=Path("runtime-validation-output"))
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--restore-journal", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.restore_journal is not None:
        try:
            result = restore_overlay(args.restore_journal, cleanup=True)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (OSError, ValidationError, ValueError) as exc:
            print(f"rollback failed: {exc}")
            return 1
    if not args.server_root:
        raise SystemExit("--server-root or CS2_SERVER_ROOT is required")
    if not args.preflight_only:
        if args.run_id is None and args.tag is None and args.artifact_dir is None:
            raise SystemExit("one of --run-id, --tag, or --artifact-dir is required")
        if not isinstance(args.expected_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
            raise SystemExit("--expected-commit must be a lowercase 40-character commit SHA")

    args.report_dir = args.report_dir.resolve()
    try:
        validate_report_location(Path(args.server_root).resolve(strict=True), args.report_dir)
    except FileNotFoundError:
        pass
    except ValidationError as exc:
        raise SystemExit(str(exc)) from exc
    args.report_dir.mkdir(parents=True, exist_ok=True)
    log_dir = args.report_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    report = {
        "schema": REPORT_SCHEMA,
        "started_at": utc_now(),
        "repository": args.repository,
        "expected_commit": args.expected_commit,
        "server_root": str(Path(args.server_root).resolve()),
        "result": "failure",
        "artifact": {},
        "preflight": {},
        "runtime": {},
        "shutdown": {},
        "rollback": {},
        "evidence": {},
    }
    return_code = 1
    try:
        return_code = run_validation(args, report, log_dir)
        if report.get("rollback", {}).get("status") != "restored" and not args.preflight_only:
            report["result"] = "failure"
            return_code = 1
    except (OSError, UnicodeError, ValueError, ValidationError, subprocess.SubprocessError) as exc:
        report["error"] = str(exc)
        return_code = 1
    finally:
        report["finished_at"] = utc_now()
        report_path = args.report_dir / "runtime-validation.json"
        write_json_atomic(report_path, report)
        write_log_archive(log_dir, args.report_dir / "runtime-validation-logs.zip")
        print(f"runtime report: {report_path}")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
