from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import runtime_validate


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sentinel_config(dependency_digest: str | None = None) -> dict:
    return {
        "schema_version": 2,
        "purpose": "vip-ci-test-server",
        "production": False,
        "expected_server_build_id": 123456,
        "map": "de_dust2",
        "game_directory": "game/csgo",
        "server_command": ["game/bin/linuxsteamrt64/cs2"],
        "server_build_id_file": "steamapps/appmanifest_730.acf",
        "minimum_free_gib": 0,
        "startup_timeout_seconds": 30,
        "shutdown_timeout_seconds": 5,
        "a2s": {"host": "127.0.0.1", "port": 27015, "timeout_seconds": 1},
        "runtime_dependencies": [
            {
                "kind": "metamod",
                "name": "Metamod:Source",
                "path": "game/csgo/addons/metamod/bin/linuxsteamrt64/server.so",
                "version": "2.0.0",
                "sha256": dependency_digest or digest(b"metamod"),
            },
            {
                "kind": "plugin",
                "name": "FakeMenus",
                "metamod_name": "FakeMenus",
                "path": "game/csgo/addons/fakemenus/bin/linuxsteamrt64/fakemenus.so",
                "version": "1.3.0",
                "sha256": digest(b"fakemenus"),
            },
        ],
        "additional_arguments": [],
    }


def write_sentinel(root: Path, config: dict) -> dict:
    (root / runtime_validate.SENTINEL).write_text(json.dumps(config), encoding="utf-8")
    return runtime_validate.load_sentinel(root)


class SentinelAndPreflightTests(unittest.TestCase):
    def test_missing_sentinel_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(runtime_validate.ValidationError, "sentinel"):
                runtime_validate.load_sentinel(Path(temporary))

    def test_legacy_sentinel_is_rejected_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = sentinel_config()
            del config["schema_version"]
            (root / runtime_validate.SENTINEL).write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(runtime_validate.ValidationError, "schema_version must be 2"):
                runtime_validate.load_sentinel(root)

    def test_placeholder_duplicate_and_invalid_digest_are_rejected(self):
        cases = []
        placeholder = sentinel_config()
        placeholder["runtime_dependencies"][0]["version"] = "REPLACE_ME"
        cases.append(placeholder)
        duplicate = sentinel_config()
        duplicate["runtime_dependencies"][1]["name"] = "metamod:source"
        cases.append(duplicate)
        zero_digest = sentinel_config()
        zero_digest["runtime_dependencies"][0]["sha256"] = "0" * 64
        cases.append(zero_digest)
        for config in cases:
            with self.subTest(config=config), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / runtime_validate.SENTINEL).write_text(json.dumps(config), encoding="utf-8")
                with self.assertRaises(runtime_validate.ValidationError):
                    runtime_validate.load_sentinel(root)

    def test_preflight_requires_exact_build_and_dependency_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "game/bin/linuxsteamrt64/cs2"
            metamod = root / "game/csgo/addons/metamod/bin/linuxsteamrt64/server.so"
            fakemenus = root / "game/csgo/addons/fakemenus/bin/linuxsteamrt64/fakemenus.so"
            manifest = root / "steamapps/appmanifest_730.acf"
            for path, content in ((binary, b"server"), (metamod, b"metamod"), (fakemenus, b"fakemenus")):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            manifest.parent.mkdir(parents=True)
            manifest.write_text('"buildid" "123456"', encoding="utf-8")
            os.chmod(binary, 0o755)
            config = write_sentinel(root, sentinel_config())
            with mock.patch("runtime_validate.platform.system", return_value="Linux"), mock.patch(
                "runtime_validate.running_server_processes", return_value=[]
            ):
                result = runtime_validate.preflight(root, config)
            self.assertEqual(result["server_build_id"], 123456)
            self.assertEqual(result["dependencies"][0]["sha256"], digest(b"metamod"))

            config["expected_server_build_id"] += 1
            with mock.patch("runtime_validate.platform.system", return_value="Linux"), mock.patch(
                "runtime_validate.running_server_processes", return_value=[]
            ), self.assertRaisesRegex(runtime_validate.ValidationError, "build ID mismatch"):
                runtime_validate.preflight(root, config)

    def test_safe_child_rejects_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(runtime_validate.ValidationError):
                runtime_validate.safe_child(Path(temporary), "../production")


class OverlayJournalTests(unittest.TestCase):
    def make_overlay(self, root: Path) -> tuple[Path, Path, Path]:
        source = root / "source"
        target = root / "target"
        report = root / "report"
        (source / "addons/vip").mkdir(parents=True)
        (target / "addons/vip").mkdir(parents=True)
        report.mkdir()
        (target / "addons/vip/vip.so").write_bytes(b"original")
        (source / "addons/vip/vip.so").write_bytes(b"replacement")
        (source / "addons/vip/new.cfg").write_bytes(b"new")
        return source, target, report

    def test_happy_path_and_second_restore_are_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, target, report = self.make_overlay(Path(temporary))
            journal = runtime_validate.create_overlay_journal(source, target, report)
            self.assertEqual((target / "addons/vip/vip.so").read_bytes(), b"replacement")
            runtime_validate.restore_overlay(journal)
            self.assertEqual((target / "addons/vip/vip.so").read_bytes(), b"original")
            self.assertFalse((target / "addons/vip/new.cfg").exists())
            result = runtime_validate.restore_overlay(journal)
            self.assertTrue(all(item["state"].startswith("already-") for item in result["files"]))

    def test_missing_or_changed_backup_is_preserved_as_failure(self):
        for mode in ("missing", "changed"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                source, target, report = self.make_overlay(Path(temporary))
                journal_path = runtime_validate.create_overlay_journal(source, target, report)
                journal = runtime_validate.load_journal(journal_path)
                backup = Path(journal["backup_root"]) / "addons/vip/vip.so"
                if mode == "missing":
                    backup.unlink()
                else:
                    backup.write_bytes(b"tampered")
                with self.assertRaisesRegex(runtime_validate.ValidationError, "preserved"):
                    runtime_validate.restore_overlay(journal_path, cleanup=True)
                self.assertTrue(journal_path.exists())
                self.assertTrue(Path(journal["backup_root"]).exists())

    def test_restore_retry_succeeds_after_first_copy_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, target, report = self.make_overlay(Path(temporary))
            journal = runtime_validate.create_overlay_journal(source, target, report)
            real_copy = runtime_validate.atomic_copy
            failures = 0

            def fail_once(source_path, destination_path):
                nonlocal failures
                if "rollback-backup" in str(source_path) and failures == 0:
                    failures += 1
                    raise OSError("transient copy failure")
                return real_copy(source_path, destination_path)

            with mock.patch("runtime_validate.atomic_copy", side_effect=fail_once):
                result = runtime_validate.restore_overlay_with_retry(journal)
            self.assertEqual(result["attempts"], 2)
            self.assertEqual((target / "addons/vip/vip.so").read_bytes(), b"original")
            self.assertFalse(journal.exists())

    def test_changed_new_file_and_directory_destination_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, target, report = self.make_overlay(Path(temporary))
            journal = runtime_validate.create_overlay_journal(source, target, report)
            new_file = target / "addons/vip/new.cfg"
            new_file.write_bytes(b"operator change")
            with self.assertRaisesRegex(runtime_validate.ValidationError, "changed after installation"):
                runtime_validate.restore_overlay(journal)

        with tempfile.TemporaryDirectory() as temporary:
            source, target, report = self.make_overlay(Path(temporary))
            journal = runtime_validate.create_overlay_journal(source, target, report)
            existing = target / "addons/vip/vip.so"
            existing.unlink()
            existing.mkdir()
            with self.assertRaisesRegex(runtime_validate.ValidationError, "not a regular file"):
                runtime_validate.restore_overlay(journal)

    @unittest.skipIf(os.name == "nt", "ordinary Windows users cannot create symlinks")
    def test_symlink_destination_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, target, report = self.make_overlay(Path(temporary))
            journal = runtime_validate.create_overlay_journal(source, target, report)
            destination = target / "addons/vip/vip.so"
            destination.unlink()
            destination.symlink_to(target / "elsewhere")
            with self.assertRaisesRegex(runtime_validate.ValidationError, "link"):
                runtime_validate.restore_overlay(journal)


class RuntimeEvidenceTests(unittest.TestCase):
    def evidence_log(self, nonce: str) -> str:
        return "\n".join(
            (
                "Metamod:Source version 2.0.0",
                "[01] FakeMenus 1.3.0",
                f'[VIP-CI] {{"event":"interfaces","nonce":"{nonce}","legacy":true,"v2":true}}',
                f'[VIP-CI] {{"event":"core_ready","nonce":"{nonce}","ready":true,"version":"1.2.3"}}',
            )
        )

    def test_structured_evidence_requires_nonce_unique_events_and_readiness(self):
        config = sentinel_config()
        result = runtime_validate.parse_runtime_evidence(self.evidence_log("abc"), "abc", config)
        self.assertTrue(result["interfaces"]["v2"])
        for text, pattern in (
            (self.evidence_log("wrong"), "nonce"),
            (self.evidence_log("abc").splitlines()[0], "IVIPApi"),
            (self.evidence_log("abc") + "\n" + self.evidence_log("abc").splitlines()[2], "duplicate"),
            (self.evidence_log("abc") + "\nfatal error", "forbidden"),
            ("[VIP-CI] not-json", "malformed"),
        ):
            with self.subTest(pattern=pattern), self.assertRaisesRegex(runtime_validate.ValidationError, pattern):
                runtime_validate.parse_runtime_evidence(text, "abc", config)

    def test_a2s_info_parser_reads_exact_map(self):
        payload = self.a2s_payload()
        result = runtime_validate.parse_a2s_info_payload(payload)
        self.assertEqual(result["map"], "de_dust2")
        self.assertEqual(result["app_id"], 730)

    @staticmethod
    def a2s_payload():
        return (
            b"\xff\xff\xff\xffI\x11"
            b"Test Server\0de_dust2\0csgo\0Counter-Strike 2\0"
            + struct.pack("<H", 730)
            + bytes((1, 32, 0, ord("d"), ord("l"), 0, 1))
            + b"1.42.0.0\0"
        )

    def test_a2s_query_handles_challenge_response(self):
        challenge = b"\xff\xff\xff\xffA\x01\x02\x03\x04"
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recvfrom.side_effect = [
            (challenge, ("127.0.0.1", 27015)),
            (self.a2s_payload(), ("127.0.0.1", 27015)),
        ]
        with mock.patch("runtime_validate.socket.socket", return_value=connection), mock.patch(
            "runtime_validate.socket.gethostbyname", return_value="127.0.0.1"
        ):
            result = runtime_validate.query_a2s_info("localhost", 27015, 1)
        self.assertEqual(result["map"], "de_dust2")
        sent = [call.args[0] for call in connection.sendto.call_args_list]
        self.assertEqual(len(sent), 2)
        self.assertTrue(sent[1].endswith(b"\x01\x02\x03\x04"))


class ProcessAndSupplyChainTests(unittest.TestCase):
    def test_process_already_exited_is_not_signalled(self):
        process = mock.Mock(returncode=0)
        process.poll.return_value = 0
        with mock.patch("runtime_validate.os.killpg", create=True) as kill:
            result = runtime_validate.terminate_process_group(process, 1)
        kill.assert_not_called()
        self.assertEqual(result["status"], "already-exited")

    def test_process_escalates_from_term_to_kill(self):
        process = mock.Mock(pid=123, returncode=-9)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("cs2", 1), -9]
        with mock.patch("runtime_validate.os.killpg", create=True) as kill:
            result = runtime_validate.terminate_process_group(process, 1)
        self.assertEqual([call.args[1] for call in kill.call_args_list], [runtime_validate.SIGTERM, runtime_validate.SIGKILL])
        self.assertEqual(result["status"], "killed")

    def test_process_lookup_races_are_already_exited(self):
        process = mock.Mock(pid=123, returncode=0)
        process.poll.side_effect = [None, 0]
        with mock.patch("runtime_validate.os.killpg", side_effect=ProcessLookupError, create=True):
            result = runtime_validate.terminate_process_group(process, 1)
        self.assertEqual(result["status"], "already-exited")

    def test_process_exit_race_before_sigkill_is_successful_shutdown(self):
        process = mock.Mock(pid=123, returncode=0)
        process.poll.side_effect = [None, 0]
        process.wait.side_effect = subprocess.TimeoutExpired("cs2", 1)
        with mock.patch(
            "runtime_validate.os.killpg",
            side_effect=[None, ProcessLookupError],
            create=True,
        ):
            result = runtime_validate.terminate_process_group(process, 1)
        self.assertEqual(result["status"], "exited-before-kill")

    def test_attestation_verification_has_explicit_spdx_predicate(self):
        with mock.patch("runtime_validate.run_checked", return_value="") as run:
            runtime_validate.verify_attestations(Path("vip.zip"), Path("vip.spdx.json"), "owner/repo")
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 3)
        self.assertIn("--predicate-type", commands[1])
        self.assertIn(runtime_validate.SPDX_PREDICATE, commands[1])

    def test_run_candidate_metadata_is_exact(self):
        args = mock.Mock(
            artifact_dir=None,
            run_id=99,
            tag=None,
            expected_commit="a" * 40,
            repository="owner/repo",
        )
        metadata = {
            "databaseId": 99,
            "headSha": "b" * 40,
            "headBranch": "PR",
            "event": "push",
            "conclusion": "success",
        }
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "runtime_validate.run_json", return_value=metadata
        ), self.assertRaisesRegex(runtime_validate.ValidationError, "headSha"):
            runtime_validate.acquire_artifacts(args, Path(temporary))


if __name__ == "__main__":
    unittest.main()
