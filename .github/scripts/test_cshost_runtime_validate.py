#!/usr/bin/env python3
"""Unit contracts for the remote CSHOST runtime validator."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import cshost_runtime_validate as runtime


SHA = "1" * 64
COMMIT = "a" * 40


def sentinel() -> dict:
    dependencies = []
    for index, capability in enumerate(("metamod", "utils", "menus", "players", "sqlmm", "cookies"), 1):
        dependencies.append({
            "capability": capability,
            "name": capability,
            "version": "1.0.0",
            "path": f"addons/runtime/{capability}.so",
            "sha256": f"{index:x}" * 64,
            "optional": capability == "cookies",
        })
    return {
        "schema": runtime.SENTINEL_SCHEMA,
        "purpose": "vip-ci-test-server",
        "production": False,
        "stage_id": "f" * 64,
        "plugin_path": runtime.PLUGIN_PATH,
        "evidence_directory": runtime.EVIDENCE_DIRECTORY,
        "startup_timeout_seconds": 60,
        "shutdown_timeout_seconds": 30,
        "probe_timeout_seconds": 60,
        "a2s": {"host": "test.invalid", "port": 27015},
        "runtime_dependencies": dependencies,
    }


def encoded_sentinel(value: dict | None = None) -> tuple[bytes, str]:
    payload = json.dumps(value or sentinel(), sort_keys=True).encode()
    return payload, hashlib.sha256(payload).hexdigest()


class FakeFTP:
    def __init__(self, files: dict[str, bytes]):
        self.files = files

    def exists(self, path: str) -> bool:
        return path in self.files

    def download(self, path: str) -> bytes:
        if path not in self.files:
            raise runtime.ValidationError(f"missing {path}")
        return self.files[path]

    def rename(self, source: str, destination: str) -> None:
        self.files[destination] = self.files.pop(source)

    def delete(self, path: str, *, missing_ok: bool = False) -> None:
        if path not in self.files and not missing_ok:
            raise runtime.ValidationError(f"missing {path}")
        self.files.pop(path, None)


class FakeAPI:
    def __init__(self, online: bool):
        self.online = online

    def is_online(self) -> bool:
        return self.online

    def start(self, _timeout: int) -> None:
        self.online = True

    def stop(self, _timeout: int) -> None:
        self.online = False


class CshostRuntimeTests(unittest.TestCase):
    def test_sentinel_is_hash_pinned_and_non_production(self):
        payload, digest = encoded_sentinel()
        config = runtime.load_sentinel(payload, digest)
        self.assertEqual(runtime.REQUIRED_CAPABILITIES, {
            item["capability"] for item in config["runtime_dependencies"] if not item["optional"]
        })
        with self.assertRaisesRegex(runtime.ValidationError, "SHA-256"):
            runtime.load_sentinel(payload, "2" * 64)
        unsafe = sentinel()
        unsafe["production"] = True
        payload, digest = encoded_sentinel(unsafe)
        with self.assertRaisesRegex(runtime.ValidationError, "non-production"):
            runtime.load_sentinel(payload, digest)

    def test_sentinel_rejects_sensitive_or_incomplete_dependency_manifest(self):
        unsafe = sentinel()
        unsafe["runtime_dependencies"][1]["path"] = "addons/configs/databases.cfg"
        payload, digest = encoded_sentinel(unsafe)
        with self.assertRaises(runtime.ValidationError):
            runtime.load_sentinel(payload, digest)
        incomplete = sentinel()
        incomplete["runtime_dependencies"] = incomplete["runtime_dependencies"][:-2]
        payload, digest = encoded_sentinel(incomplete)
        with self.assertRaisesRegex(runtime.ValidationError, "missing required"):
            runtime.load_sentinel(payload, digest)

    def test_candidate_extracts_only_exact_binary_and_embedded_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "vip.spdx.json").write_text("{}", encoding="utf-8")
            with zipfile.ZipFile(root / "vip.zip", "w") as archive:
                archive.writestr(runtime.PLUGIN_PATH, b"prefix" + COMMIT.encode() + b"suffix")
                archive.writestr("addons/configs/databases.cfg", b"must-not-be-installed")
            candidate = runtime.load_candidate(root, COMMIT)
            self.assertEqual(candidate["binary"], b"prefix" + COMMIT.encode() + b"suffix")
            with self.assertRaisesRegex(runtime.ValidationError, "VIP_BUILD_COMMIT"):
                runtime.load_candidate(root, "b" * 40)

    def test_probe_is_nonce_commit_abi_and_schema_bound(self):
        nonce = "c" * 32
        probe = {
            "schema": runtime.PROBE_SCHEMA,
            "nonce": nonce,
            "build_commit": COMMIT,
            "version": "1.2.3.1",
            "interfaces": {"IVIPApi001": True, "IVIPApi002": True},
            "ready": True,
            "migration": {"status": "ready", "account_id_type": "bigint unsigned"},
        }
        self.assertEqual(runtime.validate_probe(probe, nonce, COMMIT), probe)
        probe["migration"]["account_id_type"] = "bigint"
        with self.assertRaises(runtime.ValidationError):
            runtime.validate_probe(probe, nonce, COMMIT)

    def test_journal_restore_recovers_binary_and_original_state(self):
        original = b"original"
        candidate = b"candidate"
        backup = ".vip-ci/backups/vip.so.1.abc"
        journal = {
            "schema": runtime.JOURNAL_SCHEMA,
            "plugin_path": runtime.PLUGIN_PATH,
            "backup_path": backup,
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
            "original_online": True,
        }
        ftp = FakeFTP({
            runtime.PLUGIN_PATH: candidate,
            backup: original,
            runtime.JOURNAL_PATH: json.dumps(journal).encode(),
        })
        api = FakeAPI(True)
        result = runtime.restore_from_journal(
            api, ftp, {"startup_timeout_seconds": 30, "shutdown_timeout_seconds": 30}, journal
        )
        self.assertEqual(ftp.files[runtime.PLUGIN_PATH], original)
        self.assertNotIn(runtime.JOURNAL_PATH, ftp.files)
        self.assertTrue(api.online)
        self.assertEqual(result["result"], "success")

    def test_transport_contract_is_plain_ftp_and_fixed_public_paths(self):
        source = Path(runtime.__file__).read_text(encoding="utf-8")
        self.assertIn("ftplib.FTP()", source)
        self.assertNotIn("FTP_TLS", source)
        self.assertIn('PLUGIN_PATH = "addons/vip/vip.so"', source)
        self.assertIn('EVIDENCE_DIRECTORY = "addons/data"', source)
        self.assertNotIn("databases.cfg\")", source)


if __name__ == "__main__":
    unittest.main()
