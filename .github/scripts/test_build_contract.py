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
    for required in (
        "clang-18", "--targets x86_64", "actions/cache/restore@", "actions/cache/save@",
        "external/SchemaEntity", "update_release_tag.sh", "SDK_CACHE_MATCHED_KEY",
        "PIP_CACHE_MATCHED_KEY", "SYSTEM_SETUP_SECONDS", "prepare-build-tools.outputs.python-version",
        "--schemaentity-root", "SOURCE_DATE_EPOCH", "create_reproducible_archive.py",
        "verify_elf_hardening.py", "cmp build/package/addons/vip/vip.so", "--require-hashes",
        "abi_legacy_probe.cpp", "abi_v2_probe.cpp",
    ):
        if required not in workflow:
            failures.append(f"workflow requirement is missing: {required}")
    for required in ("-fstack-protector-strong", "_FORTIFY_SOURCE=3", "-Wdate-time", "-z,relro,-z,now,-z,noexecstack"):
        if required not in build:
            failures.append(f"hardening requirement is missing: {required}")
    if "builder.sourcePath, '..', 'SchemaEntity'" in (ROOT / "AMBuilder").read_text(encoding="utf-8"):
        failures.append("AMBuilder must not discover SchemaEntity outside the checkout")
    if failures:
        print("VIP Core build contract failed:", *failures, sep="\n- ")
        return 1
    print("VIP Core build contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
