from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("apply_sdk_compatibility_patches.py")


class SdkCompatibilityPatcherTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        sdk = root / "sdk"
        schema = root / "schema"
        manifest = root / "cs2.json"
        files = {
            sdk / "common/network_connection.proto": "message Test {}\n",
            sdk / "public/tier1/keyvalues3.h": "if(initial_size <= NODE::DATA_SIZE)\n",
            sdk / "public/bitvec.h": "if ( this->Base()[i] != ~0 )\n",
            sdk / "public/tier1/utlsymbollarge.h": "id >= m_MemBlocks.Count()\n",
            sdk / "public/tier1/memblockallocator.h": "page_size = MAX( page_size, m_nPageSize );\n",
            sdk / "public/tier1/utlhashtable.h": "for ( int i = 0; i < data.Count(); ++i )\n",
            sdk / "public/tier1/generichash.h": "#pragma once\n",
            sdk / "public/game/server/.keep": "required include root\n",
            schema / "globaltypes.h": '#include "schemasystem.h"\n',
            schema / "schemasystem.cpp": "NetworkStateChanged_t value;\n",
            schema / "CCSPlayerPawn.h": "FL_PAWN_FAKECLIENT\n",
            schema / "CCSPlayerController.h": "FL_CONTROLLER_FAKECLIENT\n",
            schema / "ctimer.h": "class CTimerBase {\npublic:\n};\n",
            schema / "module.cpp": "CMemory CModule::FindPattern(const char *pattern) {}\n",
        }
        for path, content in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
        manifest.write_text(
            '{"include_paths":["public/game/server","missing/include"]}\n',
            encoding="utf-8",
            newline="\n",
        )
        return sdk, schema, manifest

    def run_patcher(self, sdk: Path, schema: Path, manifest: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable, str(SCRIPT), "--sdk-root", str(sdk),
                "--schema-root", str(schema), "--manifest-path", str(manifest),
                "--require-include", "public/game/server",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    @staticmethod
    def snapshot(root: Path) -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in sorted(root.rglob("*")) if path.is_file()
        }

    def test_second_run_is_byte_for_byte_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, schema, manifest = self.fixture(root)
            first = self.run_patcher(sdk, schema, manifest)
            self.assertEqual(first.returncode, 0, first.stdout)
            after_first = self.snapshot(root)
            second = self.run_patcher(sdk, schema, manifest)
            self.assertEqual(second.returncode, 0, second.stdout)
            self.assertEqual(after_first, self.snapshot(root))
            module = (schema / "module.cpp").read_text(encoding="utf-8")
            self.assertEqual(module.count("__attribute__((noinline))"), 1)

    def test_missing_pattern_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, schema, manifest = self.fixture(root)
            (sdk / "public/tier1/keyvalues3.h").write_text("no match\n", encoding="utf-8")
            result = self.run_patcher(sdk, schema, manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected exactly one original or patched", result.stdout)

    def test_duplicate_pattern_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, schema, manifest = self.fixture(root)
            pattern = "if(initial_size <= NODE::DATA_SIZE)\n"
            (sdk / "public/tier1/keyvalues3.h").write_text(pattern * 2, encoding="utf-8")
            result = self.run_patcher(sdk, schema, manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("original=2", result.stdout)

    def test_mixed_original_and_patched_patterns_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, schema, manifest = self.fixture(root)
            source = "if(initial_size <= NODE::DATA_SIZE)\n"
            patched = "if(static_cast<size_t>(initial_size) <= NODE::DATA_SIZE)\n"
            (sdk / "public/tier1/keyvalues3.h").write_text(source + patched, encoding="utf-8")
            result = self.run_patcher(sdk, schema, manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mixed original and patched", result.stdout)


if __name__ == "__main__":
    unittest.main()
