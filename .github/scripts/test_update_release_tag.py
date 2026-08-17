"""Contract tests for the floating branch-tag CI helper."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import textwrap
import unittest


SCRIPT = Path(__file__).with_name("update_release_tag.sh")
SHA = "a" * 40

FAKE_GH = r'''#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_GH_LOG"
method=GET
endpoint="$2"
if [[ "$2" == --method ]]; then
  method="$3"
  endpoint="$4"
fi
reads=0
[[ ! -f "$FAKE_GH_STATE" ]] || reads="$(cat "$FAKE_GH_STATE")"
if [[ "$SCENARIO" == read-error && "$method" == GET ]]; then
  echo 'gh: Forbidden (HTTP 403)' >&2
  exit 1
fi
if [[ "$method" == GET ]]; then
  reads=$((reads + 1))
  echo "$reads" > "$FAKE_GH_STATE"
  if [[ "$SCENARIO" == missing && "$reads" -eq 1 ]]; then
    echo 'gh: Not Found (HTTP 404)' >&2
    exit 1
  fi
  result_sha="$GITHUB_SHA"
  [[ "$SCENARIO" != mismatch || "$reads" -le 1 ]] || result_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  printf '{"object":{"type":"commit","sha":"%s"}}\n' "$result_sha"
  exit 0
fi
if [[ "$method" == PATCH ]]; then
  [[ "$endpoint" == repos/bywinsty/cs2-vip/git/refs/tags/dev-core ]] || exit 2
  echo '{}'
  exit 0
fi
if [[ "$method" == POST ]]; then
  [[ "$endpoint" == repos/bywinsty/cs2-vip/git/refs ]] || exit 2
  echo '{}'
  exit 0
fi
exit 2
'''


class UpdateReleaseTagTests(unittest.TestCase):
    def run_helper(self, scenario: str):
        with tempfile.TemporaryDirectory(dir=SCRIPT.parents[2]) as directory:
            root = Path(directory)
            fake_gh = root / "gh"
            fake_gh.write_text(textwrap.dedent(FAKE_GH), encoding="utf-8", newline="\n")
            fake_gh.chmod(0o755)
            environment = {
                "GH_BIN": f"./{root.name}/gh",
                "SCENARIO": scenario,
                "FAKE_GH_STATE": f"./{root.name}/state",
                "FAKE_GH_LOG": f"./{root.name}/calls.log",
                "GITHUB_REPOSITORY": "bywinsty/cs2-vip",
                "GITHUB_REF_NAME": "dev-core",
                "GITHUB_SHA": SHA,
                "GITHUB_RUN_ID": "123",
                "GITHUB_STEP_SUMMARY": f"./{root.name}/summary.md",
                "RELEASE_TAG": "dev-core",
            }
            exports = " ".join(f"{key}={shlex.quote(value)}" for key, value in environment.items())
            result = subprocess.run(
                ["bash", "-c", f"export {exports}; bash .github/scripts/update_release_tag.sh"],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                env=os.environ,
                cwd=SCRIPT.parents[2],
                check=False,
            )
            calls_file = root / "calls.log"
            calls = calls_file.read_text(encoding="utf-8").splitlines() if calls_file.exists() else []
            summary_file = root / "summary.md"
            return result, calls, summary_file.read_text(encoding="utf-8") if summary_file.exists() else ""

    def test_existing_ref_is_updated_via_canonical_endpoint(self):
        result, calls, summary = self.run_helper("existing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"api --method PATCH repos/bywinsty/cs2-vip/git/refs/tags/dev-core -f sha={SHA} -F force=true", calls)
        self.assertNotIn("git/ref/tags/dev-core", "\n".join(call for call in calls if "--method" in call))
        self.assertIn("type=commit", summary)

    def test_missing_ref_is_created_only_after_a_404(self):
        result, calls, _ = self.run_helper("missing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"api --method POST repos/bywinsty/cs2-vip/git/refs -f ref=refs/tags/dev-core -f sha={SHA}", calls)

    def test_non_404_read_error_is_diagnostic_failure(self):
        result, _, summary = self.run_helper("read-error")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 403", result.stdout)
        self.assertIn("branch=dev-core tag=dev-core", result.stdout)
        self.assertIn("Branch tag update failed", summary)

    def test_final_ref_must_point_to_the_run_commit(self):
        result, _, summary = self.run_helper("mismatch")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Branch tag verification failed", summary)


if __name__ == "__main__":
    unittest.main()
