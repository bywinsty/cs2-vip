#!/usr/bin/env python3
"""Static checks for the single-target VIP Core build contract."""

from pathlib import Path
import json
import re


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    build = (ROOT / "AMBuildScript").read_text(encoding="utf-8")
    package = (ROOT / "PackageScript").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    prepare_tools = (ROOT / ".github/actions/prepare-build-tools/action.yml").read_text(encoding="utf-8")
    compatibility_patches = (ROOT / ".github/scripts/apply_sdk_compatibility_patches.py").read_text(encoding="utf-8")
    dependency_manifest = json.loads(
        (ROOT / ".github/dependency-manifest.json").read_text(encoding="utf-8")
    )
    dependencies = {item["capability"]: item for item in dependency_manifest["dependencies"]}
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
        "/__w/_temp/vip.zip", "/__w/_temp/vip.spdx.json",
        "--schemaentity-root", "--disable-debug", "SOURCE_DATE_EPOCH", "create_reproducible_archive.py",
        "verify_elf_hardening.py", "test_verify_elf_hardening.py",
        "cmp build/package/addons/vip/vip.so", "--require-hashes",
        "abi_legacy_probe.cpp", "abi_v2_probe.cpp",
        "VIP_BUILD_COMMIT: ${{ github.sha }}",
        "dependency-manifest.json", "verify_spdx_dependencies.py",
        "test_sdk_compatibility_patches.py", "hash_file_tree.py",
        "sdk-patched-first.sha256", "sdk-patched-second.sha256",
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
    if "${{ runner.temp }}/vip" in workflow:
        failures.append("container artifacts must not use the host runner.temp expression")
    if "/opt/python/cp312-cp312/bin" not in prepare_tools:
        failures.append("build tools must use the Python bundled with the manylinux image")
    if "actions/setup-python@" in prepare_tools:
        failures.append("manylinux build must not inject a host-glibc Python runtime")
    if "ensure_noinline_pattern_scan" not in compatibility_patches or '__attribute__((noinline))' not in compatibility_patches:
        failures.append("GCC 14 SchemaEntity pattern-scan compatibility patch is missing")
    if "patch_gcc14_signedness" not in compatibility_patches or "static_cast<uint32>(0)" not in compatibility_patches:
        failures.append("GCC 14 HL2SDK signedness compatibility patches are missing")
    for required in ("-fstack-protector-strong", "_FORTIFY_SOURCE=2", "-Wdate-time", "-ffile-prefix-map", "-z,relro,-z,now,-z,noexecstack"):
        if required not in build:
            failures.append(f"hardening requirement is missing: {required}")
    if "builder.sourcePath, '..', 'SchemaEntity'" in (ROOT / "AMBuilder").read_text(encoding="utf-8"):
        failures.append("AMBuilder must not discover SchemaEntity outside the checkout")
    if "__DATE__" in (ROOT / "vip.cpp").read_text(encoding="utf-8"):
        failures.append("vip.cpp must not use non-reproducible date/time macros")
    if "VIP_BUILD_COMMIT" not in build or "self.build_commit != 'local'" not in build:
        failures.append("AMBuildScript must embed and validate VIP_BUILD_COMMIT")
    if "pull_request:\n    branches:\n      - Core\n      - PR\n      - dev" not in workflow:
        failures.append("build workflow must validate merge refs targeting Core, PR and dev")
    if "pull_request_target" in workflow:
        failures.append("untrusted PR checks must not use pull_request_target")
    if "[skip ci]" in workflow:
        failures.append("protected build jobs must not implement a skip-ci success path")
    workflow_pins = {
        "ambuild": "AMBUILD_REF",
        "metamod-source": "MMS_REF",
        "hl2sdk-cs2": "HL2SDK_REF",
        "schemaentity": "SCHEMAENTITY_REF",
        "hl2sdk-manifests": "MANIFEST_REF",
    }
    for capability, environment_name in workflow_pins.items():
        version = dependencies[capability]["version"]
        if f'{environment_name}: "{version}"' not in workflow:
            failures.append(f"workflow {environment_name} drifted from dependency manifest")
    if dependencies["build-environment"]["version"].removeprefix("sha256:") not in workflow:
        failures.append("build image digest drifted from dependency manifest")
    if dependencies["protoc"]["version"] != "21.8" or dependencies["protoc"]["artifact_sha256"] not in workflow:
        failures.append("protoc pin drifted from dependency manifest")
    requirements = (ROOT / ".github/ci-requirements.txt").read_text(encoding="utf-8")
    for capability in ("python-pip", "python-setuptools", "python-importlib-metadata", "python-zipp"):
        dependency = dependencies[capability]
        if f'{dependency["name"]}=={dependency["version"]}' not in requirements:
            failures.append(f"Python tooling pin drifted from dependency manifest: {capability}")
    if failures:
        print("VIP Core build contract failed:", *failures, sep="\n- ")
        return 1
    print("VIP Core build contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
