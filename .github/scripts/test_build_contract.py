#!/usr/bin/env python3
"""Static checks for the single-target VIP Core build contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    build = (ROOT / "AMBuildScript").read_text(encoding="utf-8")
    package = (ROOT / "PackageScript").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    failures = []
    if "target_archs = ['x86_64']" not in build:
        failures.append("AMBuildScript must default to x86_64")
    if "tier1', 'generichash.cpp" in build:
        failures.append("obsolete generichash.cpp source entry must be absent")
    if "PackageScript supports exactly one target" not in package:
        failures.append("PackageScript single-target guard is missing")
    for required in ("clang-18", "--targets x86_64", "actions/cache/restore@", "actions/cache/save@"):
        if required not in workflow:
            failures.append(f"workflow requirement is missing: {required}")
    if failures:
        print("VIP Core build contract failed:", *failures, sep="\n- ")
        return 1
    print("VIP Core build contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
