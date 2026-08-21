#!/usr/bin/env python3
"""Fail when a Linux x86-64 plugin misses required ELF hardening."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess


def output(*command: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--library-path", type=Path)
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
    loader_env = os.environ.copy()
    if args.library_path:
        loader_env["LD_LIBRARY_PATH"] = str(args.library_path.resolve()) + os.pathsep + loader_env.get("LD_LIBRARY_PATH", "")
    relocations = output("ldd", "-r", binary, env=loader_env)
    if "not found" in relocations:
        raise SystemExit(f"runtime library was not found:\n{relocations}")
    if "undefined symbol:" in relocations:
        raise SystemExit(f"unresolved symbol detected:\n{relocations}")
    print(f"ELF hardening contract passed: {binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
