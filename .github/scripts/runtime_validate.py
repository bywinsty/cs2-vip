#!/usr/bin/env python3
"""Safely validate a dev release on an explicitly marked Linux CS2 test server."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import time
import zipfile


SENTINEL = ".vip-ci-test-server"
FORBIDDEN_LOG_PATTERNS = (
    "segmentation fault",
    "unresolved symbol",
    "undefined symbol",
    "interface mismatch",
    "failed to load plugin",
    "load error",
    "fatal error",
)


class ValidationError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_child(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValidationError(f"path escapes marked server root: {relative}") from exc
    return candidate


def load_sentinel(server_root: Path) -> dict:
    sentinel = server_root / SENTINEL
    if not sentinel.is_file() or sentinel.is_symlink():
        raise ValidationError(f"refusing to run without regular sentinel file {sentinel}")
    try:
        config = json.loads(sentinel.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid sentinel JSON: {exc}") from exc
    if config.get("purpose") != "vip-ci-test-server" or config.get("production") is not False:
        raise ValidationError("sentinel must declare purpose=vip-ci-test-server and production=false")
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
    game_dir = safe_child(server_root, config.get("game_directory", "game/csgo"))
    if not game_dir.is_dir():
        raise ValidationError(f"CS2 game directory is missing: {game_dir}")
    command = config.get("server_command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
        raise ValidationError("sentinel server_command must be a non-empty string array")
    server_binary = safe_child(server_root, command[0])
    if not server_binary.is_file() or not os.access(server_binary, os.X_OK):
        raise ValidationError(f"CS2 dedicated server binary is missing or not executable: {server_binary}")
    running = running_server_processes(server_binary)
    if running:
        raise ValidationError("a server process is already running: " + "; ".join(running))

    dependencies = config.get("runtime_dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValidationError("sentinel runtime_dependencies must pin Metamod and core runtime dependencies")
    dependency_results = []
    for dependency in dependencies:
        if not isinstance(dependency, dict) or not dependency.get("name") or not dependency.get("path"):
            raise ValidationError("each runtime dependency needs name and path")
        path = safe_child(server_root, dependency["path"])
        if not path.is_file():
            raise ValidationError(f"runtime dependency is missing: {dependency['name']} ({path})")
        dependency_results.append(
            {
                "name": dependency["name"],
                "path": path.relative_to(server_root).as_posix(),
                "version": dependency.get("version", "NOASSERTION"),
                "sha256": sha256(path),
            }
        )
    if not any("metamod" in item["name"].lower() for item in dependency_results):
        raise ValidationError("runtime_dependencies must include Metamod")

    minimum_free_gib = int(config.get("minimum_free_gib", 10))
    free_bytes = shutil.disk_usage(server_root).free
    if free_bytes < minimum_free_gib * 1024**3:
        raise ValidationError(
            f"insufficient free space: {free_bytes / 1024**3:.2f} GiB, need {minimum_free_gib} GiB"
        )
    build_id = "NOASSERTION"
    if config.get("server_build_id_file"):
        build_file = safe_child(server_root, config["server_build_id_file"])
        if not build_file.is_file():
            raise ValidationError(f"server build ID file is missing: {build_file}")
        build_text = build_file.read_text(encoding="utf-8", errors="replace")
        match = re.search(r'"buildid"\s+"([0-9]+)"', build_text, flags=re.IGNORECASE)
        build_id = match.group(1) if match else build_text.strip()
    return {
        "game_directory": game_dir,
        "server_binary": server_binary,
        "server_command": command,
        "dependencies": dependency_results,
        "server_build_id": build_id,
        "free_bytes": free_bytes,
    }


def run_checked(command: list[str], *, cwd: Path | None = None) -> None:
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise ValidationError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")


def verify_release(artifact_dir: Path, repository: str) -> tuple[Path, Path, dict]:
    archive = artifact_dir / "vip.zip"
    sbom = artifact_dir / "vip.spdx.json"
    if not archive.is_file() or not sbom.is_file():
        raise ValidationError("artifact directory must contain vip.zip and vip.spdx.json")
    run_checked(["gh", "attestation", "verify", str(archive), "--repo", repository])
    run_checked(["gh", "attestation", "verify", str(sbom), "--repo", repository])
    run_checked(
        [
            os.environ.get("PYTHON", "python3"),
            str(Path(__file__).with_name("verify_spdx_subject.py")),
            "--archive",
            str(archive),
            "--sbom",
            str(sbom),
        ]
    )
    document = json.loads(sbom.read_text(encoding="utf-8"))
    release = next(
        package for package in document["packages"] if package.get("SPDXID") == "SPDXRef-ReleaseArchive"
    )
    return archive, sbom, {"commit": release.get("versionInfo"), "sha256": sha256(archive)}


def extract_zip_safely(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as handle:
        seen: set[str] = set()
        for item in handle.infolist():
            normalized = Path(item.filename.replace("\\", "/"))
            if normalized.is_absolute() or ".." in normalized.parts or item.filename in seen:
                raise ValidationError(f"unsafe or duplicate archive member: {item.filename}")
            seen.add(item.filename)
            mode = item.external_attr >> 16
            if mode & 0o170000 == 0o120000:
                raise ValidationError(f"archive links are forbidden: {item.filename}")
        handle.extractall(destination)


def install_overlay(source: Path, target: Path, backup: Path) -> tuple[list[Path], list[Path]]:
    installed: list[Path] = []
    created_directories: list[Path] = []
    for directory in sorted((path for path in source.rglob("*") if path.is_dir())):
        relative = directory.relative_to(source)
        destination = safe_child(target, relative.as_posix())
        if not destination.exists():
            destination.mkdir()
            created_directories.append(destination)
    for path in sorted(item for item in source.rglob("*") if item.is_file()):
        relative = path.relative_to(source)
        destination = safe_child(target, relative.as_posix())
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                raise ValidationError(f"refusing to replace non-regular server path: {destination}")
            backup_path = safe_child(backup, relative.as_posix())
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(destination, backup_path)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        installed.append(destination)
    return installed, created_directories


def restore_overlay(installed: list[Path], created_directories: list[Path], target: Path, backup: Path) -> None:
    for destination in reversed(installed):
        relative = destination.relative_to(target)
        backup_path = backup / relative
        if backup_path.is_file():
            shutil.copy2(backup_path, destination)
        elif destination.is_file() or destination.is_symlink():
            destination.unlink()
    for directory in sorted(created_directories, key=lambda path: len(path.parts), reverse=True):
        try:
            directory.rmdir()
        except OSError:
            pass


def write_log_archive(log_directory: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in log_directory.rglob("*") if item.is_file()):
            archive.write(path, path.relative_to(log_directory).as_posix())


def launch_and_validate(server_root: Path, config: dict, preflight_result: dict, log_path: Path) -> dict:
    command = [str(preflight_result["server_binary"]), *preflight_result["server_command"][1:]]
    game_map = str(config.get("map", "de_dust2"))
    command.extend(["-dedicated", "-insecure", "-usercon", "+sv_lan", "1", "+map", game_map])
    command.extend(["+meta", "version", "+meta", "list"])
    command.extend(str(item) for item in config.get("additional_arguments", []))
    required = config.get("required_log_patterns")
    if not isinstance(required, list) or not required or not all(isinstance(item, str) for item in required):
        raise ValidationError("sentinel required_log_patterns must be a non-empty string array")
    timeout = int(config.get("startup_timeout_seconds", 180))
    with log_path.open("w", encoding="utf-8", newline="\n") as log_handle:
        process = subprocess.Popen(
            command,
            cwd=server_root,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                log_handle.flush()
                text = log_path.read_text(encoding="utf-8", errors="replace")
                lowered = text.lower()
                if any(pattern in lowered for pattern in FORBIDDEN_LOG_PATTERNS):
                    raise ValidationError("forbidden runtime error pattern found in server log")
                if all(pattern in text for pattern in required):
                    return {"command": command, "map": game_map, "required_patterns": required}
                time.sleep(1)
            text = log_path.read_text(encoding="utf-8", errors="replace")
            missing = [pattern for pattern in required if pattern not in text]
            raise ValidationError(f"server readiness/runtime markers missing after {timeout}s: {missing}")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-root", default=os.environ.get("CS2_SERVER_ROOT"))
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--repository", default="bywinsty/cs2-vip")
    parser.add_argument("--tag", default="dev")
    parser.add_argument("--report-dir", type=Path, default=Path("runtime-validation-output"))
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    if not args.server_root:
        raise SystemExit("--server-root or CS2_SERVER_ROOT is required")

    server_root = Path(args.server_root).resolve()
    report_dir = args.report_dir.resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    log_dir = report_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    report = {
        "schema": "https://github.com/bywinsty/cs2-vip/runtime-validation-v1",
        "started_at": utc_now(),
        "repository": args.repository,
        "tag": args.tag,
        "server_root": str(server_root),
        "result": "failure",
        "checks": {},
    }
    installed: list[Path] = []
    created_directories: list[Path] = []
    overlay_target: Path | None = None
    backup_root: Path | None = None
    try:
        config = load_sentinel(server_root)
        preflight_result = preflight(server_root, config)
        report["checks"]["preflight"] = {
            key: value
            for key, value in preflight_result.items()
            if key not in {"game_directory", "server_binary", "server_command"}
        }
        report["checks"]["preflight"]["game_directory"] = str(preflight_result["game_directory"])
        report["checks"]["preflight"]["server_binary"] = str(preflight_result["server_binary"])
        if args.preflight_only:
            report["result"] = "success"
            return_code = 0
        else:
            artifact_context = tempfile.TemporaryDirectory(prefix="vip-runtime-artifacts-") if args.artifact_dir is None else None
            try:
                artifact_dir = Path(artifact_context.name) if artifact_context else args.artifact_dir.resolve()
                artifact_dir.mkdir(parents=True, exist_ok=True)
                if artifact_context:
                    run_checked(
                        [
                            "gh",
                            "release",
                            "download",
                            args.tag,
                            "--repo",
                            args.repository,
                            "--pattern",
                            "vip.zip",
                            "--pattern",
                            "vip.spdx.json",
                            "--dir",
                            str(artifact_dir),
                        ]
                    )
                archive, sbom, release_info = verify_release(artifact_dir, args.repository)
                report["checks"]["release"] = {
                    **release_info,
                    "sbom_sha256": sha256(sbom),
                    "attestations": "verified",
                }
                with tempfile.TemporaryDirectory(prefix="vip-runtime-overlay-") as overlay_name, tempfile.TemporaryDirectory(
                    prefix="vip-runtime-backup-"
                ) as backup_name:
                    overlay = Path(overlay_name)
                    backup_root = Path(backup_name)
                    extract_zip_safely(archive, overlay)
                    overlay_target = preflight_result["game_directory"]
                    installed, created_directories = install_overlay(overlay, overlay_target, backup_root)
                    try:
                        report["checks"]["runtime"] = launch_and_validate(
                            server_root,
                            config,
                            preflight_result,
                            log_dir / "cs2-server.log",
                        )
                    finally:
                        restore_overlay(installed, created_directories, overlay_target, backup_root)
                        installed = []
                        created_directories = []
                report["result"] = "success"
                return_code = 0
            finally:
                if artifact_context:
                    artifact_context.cleanup()
    except (OSError, ValueError, ValidationError, subprocess.SubprocessError) as exc:
        report["error"] = str(exc)
        return_code = 1
    finally:
        if installed and overlay_target and backup_root:
            try:
                restore_overlay(installed, created_directories, overlay_target, backup_root)
                report["rollback"] = "restored"
            except OSError as exc:
                report["rollback"] = f"failed: {exc}"
                return_code = 1
        report["finished_at"] = utc_now()
        report_path = report_dir / "runtime-validation.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        write_log_archive(log_dir, report_dir / "runtime-validation-logs.zip")
        print(f"runtime report: {report_path}")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
