from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import runtime_validate


class RuntimeValidationSafetyTests(unittest.TestCase):
    def test_missing_sentinel_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(runtime_validate.ValidationError, "sentinel"):
                runtime_validate.load_sentinel(Path(temporary))

    def test_sentinel_must_explicitly_mark_non_production_server(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / runtime_validate.SENTINEL).write_text(
                json.dumps({"purpose": "vip-ci-test-server", "production": True}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(runtime_validate.ValidationError, "production=false"):
                runtime_validate.load_sentinel(root)

    def test_preflight_accepts_marked_fixture_and_pinned_metamod(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            game = root / "game/csgo"
            binary = root / "game/bin/linuxsteamrt64/cs2"
            metamod = game / "addons/metamod/bin/linuxsteamrt64/server.so"
            binary.parent.mkdir(parents=True)
            metamod.parent.mkdir(parents=True)
            game.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"server")
            metamod.write_bytes(b"metamod")
            os.chmod(binary, 0o755)
            config = {
                "server_command": ["game/bin/linuxsteamrt64/cs2"],
                "game_directory": "game/csgo",
                "minimum_free_gib": 0,
                "runtime_dependencies": [
                    {
                        "name": "Metamod:Source",
                        "path": "game/csgo/addons/metamod/bin/linuxsteamrt64/server.so",
                        "version": "pinned-test",
                    }
                ],
            }
            with mock.patch("runtime_validate.platform.system", return_value="Linux"), mock.patch(
                "runtime_validate.running_server_processes", return_value=[]
            ):
                result = runtime_validate.preflight(root, config)
            self.assertEqual(result["server_binary"], binary)
            self.assertEqual(result["dependencies"][0]["version"], "pinned-test")

    def test_safe_child_rejects_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(runtime_validate.ValidationError, "escapes"):
                runtime_validate.safe_child(Path(temporary), "../production")

    def test_overlay_restores_replaced_files_and_removes_new_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            target = root / "target"
            backup = root / "backup"
            (source / "addons/vip").mkdir(parents=True)
            (target / "addons/vip").mkdir(parents=True)
            backup.mkdir()
            existing = target / "addons/vip/vip.so"
            existing.write_bytes(b"original")
            (source / "addons/vip/vip.so").write_bytes(b"replacement")
            (source / "addons/vip/new.cfg").write_bytes(b"new")
            installed, created = runtime_validate.install_overlay(source, target, backup)
            self.assertEqual(existing.read_bytes(), b"replacement")
            runtime_validate.restore_overlay(installed, created, target, backup)
            self.assertEqual(existing.read_bytes(), b"original")
            self.assertFalse((target / "addons/vip/new.cfg").exists())


if __name__ == "__main__":
    unittest.main()
