#!/usr/bin/env python3
"""Static checks for the single-target VIP Core build contract."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    build = (ROOT / "AMBuildScript").read_text(encoding="utf-8")
    package = (ROOT / "PackageScript").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    prepare_tools = (ROOT / ".github/actions/prepare-build-tools/action.yml").read_text(encoding="utf-8")
    failures = []
    if "target_archs = ['x86_64']" not in build:
        failures.append("AMBuildScript must default to x86_64")
    if "tier1', 'generichash.cpp" in build:
        failures.append("obsolete generichash.cpp source entry must be absent")
    if "PackageScript supports exactly one target" not in package:
        failures.append("PackageScript single-target guard is missing")
    for required in (
        "BUILD_ABI", "CACHE_VERSION: \"v4\"", "GLIBC_BASELINE: \"2.28\"",
        "PROTOC_VERSION: \"21.8\"", "PROTOC_ARCHIVE_SHA256",
        "protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION", "sha256sum --check --strict",
        "CC: gcc", "CXX: g++", "--max-glibc \"$GLIBC_BASELINE\"",
        'safe.directory "$GITHUB_WORKSPACE"',
        "/__w/_temp/vip-dependencies", "/__w/_temp/pip-cache",
        "--targets x86_64", "actions/cache/restore@", "actions/cache/save@",
        "external/SchemaEntity", "update_release_tag.sh", "SDK_CACHE_MATCHED_KEY",
        "PIP_CACHE_MATCHED_KEY", "prepare-build-tools.outputs.python-version",
        "libprotoc 3.21.8",
        "--schemaentity-root", "--disable-debug", "SOURCE_DATE_EPOCH", "create_reproducible_archive.py",
        "verify_elf_hardening.py", "test_verify_elf_hardening.py",
        "cmp build/package/addons/vip/vip.so", "--require-hashes",
        "abi_legacy_probe.cpp", "abi_v2_probe.cpp",
    ):
        if required not in workflow:
            failures.append(f"workflow requirement is missing: {required}")
    image_pattern = (
        r"image:\s+quay\.io/pypa/manylinux_2_28_x86_64@sha256:[0-9a-f]{64}(?:\s|$)"
    )
    if re.search(image_pattern, workflow) is None:
        failures.append("manylinux_2_28 build image must be pinned by a full sha256 digest")
    if re.search(r'PROTOC_ARCHIVE_SHA256: "[0-9a-f]{64}"', workflow) is None:
        failures.append("the compatible protoc archive must be pinned by a full sha256 digest")
    if workflow.count('--max-glibc "$GLIBC_BASELINE"') != 2:
        failures.append("both release builds must enforce the GLIBC baseline")
    if "/opt/python/cp312-cp312/bin" not in prepare_tools:
        failures.append("build tools must use the Python bundled with the manylinux image")
    if "actions/setup-python@" in prepare_tools:
        failures.append("manylinux build must not inject a host-glibc Python runtime")
    for required in ("-fstack-protector-strong", "_FORTIFY_SOURCE=2", "-Wdate-time", "-ffile-prefix-map", "-z,relro,-z,now,-z,noexecstack"):
        if required not in build:
            failures.append(f"hardening requirement is missing: {required}")
    if "builder.sourcePath, '..', 'SchemaEntity'" in (ROOT / "AMBuilder").read_text(encoding="utf-8"):
        failures.append("AMBuilder must not discover SchemaEntity outside the checkout")
    if "__DATE__" in (ROOT / "vip.cpp").read_text(encoding="utf-8"):
        failures.append("vip.cpp must not use non-reproducible date/time macros")
    if failures:
        print("VIP Core build contract failed:", *failures, sep="\n- ")
        return 1
    print("VIP Core build contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
