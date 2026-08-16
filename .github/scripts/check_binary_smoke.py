#!/usr/bin/env python3
"""Run deterministic ELF loader/package smoke checks for one plugin package."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from validate_package import ValidationError, validate_vdf


def run_tool(*args):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True).stdout
    except FileNotFoundError as exc:
        raise ValidationError(f"required tool is not installed: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout).strip()
        raise ValidationError(f"{args[0]} failed for {args[-1]}: {detail}") from exc


def check_binary(binary):
    file_output = run_tool("file", "-b", str(binary))
    lowered = file_output.lower()
    for expected in ("elf 64-bit", "x86-64", "shared object"):
        if expected not in lowered:
            raise ValidationError(f"{binary}: file output is not an x86-64 shared object: {file_output.strip()}")

    header = run_tool("readelf", "-h", str(binary))
    required_header_fields = (
        ("Class:", "ELF64"),
        ("Data:", "little endian"),
        ("Type:", "DYN"),
        ("Machine:", "Advanced Micro Devices X86-64"),
    )
    for field, value in required_header_fields:
        if not any(line.strip().startswith(field) and value in line for line in header.splitlines()):
            raise ValidationError(f"{binary}: readelf header lacks {field} {value}")

    program_headers = run_tool("readelf", "-l", str(binary))
    if not any(line.strip().startswith("LOAD") for line in program_headers.splitlines()):
        raise ValidationError(f"{binary}: no PT_LOAD segment reported by readelf")

    dynamic = run_tool("readelf", "-d", str(binary))
    for line in dynamic.splitlines():
        if "(RPATH)" in line or "(RUNPATH)" in line:
            value = line.split("[")[-1].split("]", 1)[0]
            if any(part.startswith("/") or ".." in part.split("/") for part in value.split(":")):
                raise ValidationError(f"{binary}: unsafe absolute or parent-relative RPATH/RUNPATH: {value}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--package-key", required=True)
    parser.add_argument("--package-root", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        package = manifest["packages"][args.package_key]
        binary_path = args.package_root / package["binary"]
        vdf_path = args.package_root / package["vdf"]
        check_binary(binary_path)
        validate_vdf(vdf_path.read_bytes(), package["binary"], str(vdf_path))
        print(f"binary smoke check passed: {args.package_key}")
        return 0
    except (ValidationError, OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"binary smoke check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
