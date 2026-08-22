#!/usr/bin/env python3
"""Fail when a Linux x86-64 plugin misses required ELF hardening."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess


def output(*command: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result.stdout


GLIBC_VERSION = re.compile(r"(?<![A-Z0-9_])GLIBC_(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(value: str) -> tuple[int, ...]:
    parts = value.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        raise ValueError(f"invalid version: {value}")
    return tuple(int(part) for part in parts)


def required_glibc_versions(version_info: str) -> set[tuple[int, ...]]:
    return {
        tuple(int(part) for part in match.groups() if part is not None)
        for match in GLIBC_VERSION.finditer(version_info)
    }


def validate_glibc_baseline(version_info: str, maximum: tuple[int, ...]) -> tuple[int, ...]:
    versions = required_glibc_versions(version_info)
    if not versions:
        raise ValueError("ELF has no versioned GLIBC requirements")
    actual = max(versions)
    if actual > maximum:
        actual_text = ".".join(str(part) for part in actual)
        maximum_text = ".".join(str(part) for part in maximum)
        raise ValueError(f"GLIBC_{actual_text} exceeds supported baseline GLIBC_{maximum_text}")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--library-path", type=Path)
    parser.add_argument("--max-glibc", required=True)
    args = parser.parse_args()
    binary = str(args.binary)
    header = output("readelf", "-hW", binary)
    if "ELF64" not in header or "Advanced Micro Devices X86-64" not in header:
        raise SystemExit("binary is not ELF x86-64")
    program = output("readelf", "-lW", binary)
    stack = next((line for line in program.splitlines() if "GNU_STACK" in line), "")
    if not stack or "RWE" in stack:
        raise SystemExit("GNU_STACK is executable or missing")
    if "GNU_RELRO" not in program:
        raise SystemExit("GNU_RELRO is missing")
    dynamic = output("readelf", "-dW", binary)
    if "BIND_NOW" not in dynamic:
        raise SystemExit("full RELRO/BIND_NOW is missing")
    if "(RPATH)" in dynamic or "(RUNPATH)" in dynamic:
        raise SystemExit("unsafe RPATH/RUNPATH is present")
    if "Build ID:" not in output("readelf", "-nW", binary):
        raise SystemExit("ELF build-id is missing")
    if "__stack_chk_fail" not in output("readelf", "-sW", binary):
        raise SystemExit("stack protector symbol is missing")
    try:
        maximum_glibc = parse_version(args.max_glibc)
        actual_glibc = validate_glibc_baseline(
            output("readelf", "--version-info", "-W", binary), maximum_glibc
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    loader_env = os.environ.copy()
    if args.library_path:
        loader_env["LD_LIBRARY_PATH"] = str(args.library_path.resolve()) + os.pathsep + loader_env.get("LD_LIBRARY_PATH", "")
    relocations = output("ldd", "-r", binary, env=loader_env)
    if "not found" in relocations:
        raise SystemExit(f"runtime library was not found:\n{relocations}")
    if "undefined symbol:" in relocations:
        raise SystemExit(f"unresolved symbol detected:\n{relocations}")
    actual_glibc_text = ".".join(str(part) for part in actual_glibc)
    print(f"ELF hardening and GLIBC compatibility contract passed: {binary} (GLIBC_{actual_glibc_text})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
