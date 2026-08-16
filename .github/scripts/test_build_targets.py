#!/usr/bin/env python3
import sys
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGETS = "['x86_64']"


def main():
    manifest = json.loads(
        (ROOT / ".github/package-manifest.json").read_text(encoding="utf-8")
    )
    expected_module_count = len(manifest["packages"])
    scripts = sorted(ROOT.glob("VIP_*/**/AMBuildScript"))
    failures = []
    for path in scripts:
        text = path.read_text(encoding="utf-8")
        default_assignment = f"else:\n      target_archs = {DEFAULT_TARGETS}"
        if default_assignment not in text:
            failures.append(
                f"{path.relative_to(ROOT)}: default target_archs is not {DEFAULT_TARGETS}"
            )

    if len(scripts) != expected_module_count:
        failures.append(
            f"expected {expected_module_count} AMBuildScript files from package manifest, "
            f"found {len(scripts)}"
        )
    if failures:
        print("build target regression check failed:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1

    print(f"build target regression check passed: {len(scripts)} modules default to x86_64")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
