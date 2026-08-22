#!/usr/bin/env python3
"""Apply and validate the pinned CS2 SDK compatibility adjustments."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def ensure_include(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    source = '#include "schemasystem.h"\n'
    patched = '#include "gametrace.h"\n'
    source_count = text.count(source)
    patched_count = text.count(patched)
    if patched_count == 1 and source_count == 1:
        return
    if patched_count != 0 or source_count != 1:
        raise SystemExit(
            f"expected exactly one original or patched include state in {path}: "
            f"source={source_count}, patched={patched_count}"
        )
    write(path, text.replace(source, source + patched, 1))


def replace_or_verify(path: Path, old: str, new: str, expected_count: int = 1) -> None:
    text = path.read_text(encoding="utf-8")
    patched_count = text.count(new)
    original_count = text.count(old)
    if patched_count == expected_count:
        # Some patched forms intentionally contain the source pattern (for
        # example the noinline prefix). Remove every complete patched form
        # before looking for a mixed original+patched state.
        residual = text.replace(new, "", expected_count)
        if old in residual:
            raise SystemExit(f"mixed original and patched compatibility patterns in {path}: {old}")
        return
    if patched_count and original_count:
        raise SystemExit(f"mixed original and patched compatibility patterns in {path}: {old}")
    if patched_count > expected_count:
        raise SystemExit(f"duplicate patched compatibility pattern in {path}: {new}")
    if original_count != expected_count:
        raise SystemExit(
            f"expected exactly {expected_count} original or patched compatibility patterns in {path}: "
            f"original={original_count}, patched={patched_count}"
        )
    write(path, text.replace(old, new, expected_count))


def ensure_timer_destructor(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    destructor = "    virtual ~CTimerBase() = default;\n"
    declaration = "class CTimerBase {\npublic:\n"
    destructor_count = text.count(destructor)
    declaration_count = text.count(declaration)
    if destructor_count == 1 and declaration_count == 1:
        return
    if destructor_count != 0 or declaration_count != 1:
        raise SystemExit(
            f"expected exactly one original or patched CTimerBase state in {path}: "
            f"declaration={declaration_count}, destructor={destructor_count}"
        )
    write(path, text.replace(declaration, declaration + destructor, 1))


def ensure_noinline_pattern_scan(path: Path, expected_count: int = 1) -> None:
    old = "CMemory CModule::FindPattern("
    new = (
        "#if defined(__GNUC__) && !defined(__clang__)\n"
        "__attribute__((noinline))\n"
        "#endif\n"
        "CMemory CModule::FindPattern("
    )
    replace_or_verify(path, old, new, expected_count=expected_count)


def patch_gcc14_signedness(sdk_root: Path) -> None:
    replace_or_verify(
        sdk_root / "public" / "tier1" / "keyvalues3.h",
        "if(initial_size <= NODE::DATA_SIZE)",
        "if(static_cast<size_t>(initial_size) <= NODE::DATA_SIZE)",
    )
    replace_or_verify(
        sdk_root / "public" / "bitvec.h",
        "if ( this->Base()[i] != ~0 )",
        "if ( this->Base()[i] != ~static_cast<uint32>(0) )",
    )
    replace_or_verify(
        sdk_root / "public" / "tier1" / "utlsymbollarge.h",
        "id >= m_MemBlocks.Count()",
        "id >= static_cast<UtlSymLargeId_t>(m_MemBlocks.Count())",
        expected_count=2,
    )
    replace_or_verify(
        sdk_root / "public" / "tier1" / "memblockallocator.h",
        "page_size = MAX( page_size, m_nPageSize );",
        "page_size = MAX( page_size, static_cast<int>(m_nPageSize) );",
    )
    replace_or_verify(
        sdk_root / "public" / "tier1" / "utlhashtable.h",
        "for ( int i = 0; i < data.Count(); ++i )",
        "for ( size_t i = 0; i < data.Count(); ++i )",
    )


def patch_proto(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    syntax = [line.strip() for line in text.splitlines() if line.strip().startswith("syntax = ")]
    if not syntax:
        write(path, 'syntax = "proto2";\n' + text)
    elif syntax != ['syntax = "proto2";']:
        raise SystemExit(f"unsupported protobuf syntax in {path}: {syntax}")


def patch_manifest(path: Path, sdk_root: Path, required_includes: list[str]) -> None:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    include_paths = manifest.get("include_paths")
    if not isinstance(include_paths, list):
        raise SystemExit(f"manifest include_paths is not a list: {path}")
    filtered = [item for item in include_paths if isinstance(item, str) and (sdk_root / item).is_dir()]
    for required in required_includes:
        if (sdk_root / required).is_dir() and required not in filtered:
            raise SystemExit(f"manifest lost required include: {required}")
    if filtered != include_paths:
        manifest["include_paths"] = filtered
        write(path, json.dumps(manifest, indent=4) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--manifest-path", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--proto-path", type=Path)
    parser.add_argument("--require-include", action="append", default=[])
    args = parser.parse_args()

    sdk_root = args.sdk_root
    patch_proto(args.proto_path or sdk_root / "common" / "network_connection.proto")
    patch_manifest(args.manifest_path, sdk_root, args.require_include or ["public/game/server"])
    patch_gcc14_signedness(sdk_root)
    schema = args.schema_root
    ensure_include(schema / "globaltypes.h")
    replace_or_verify(
        schema / "schemasystem.cpp",
        "NetworkStateChanged_t data",
        "NetworkStateChangedData data",
        expected_count=2,
    )
    replace_or_verify(
        schema / "schemasystem.cpp",
        "NetworkStateChanged_t(nLocalOffset",
        "NetworkStateChangedData(nLocalOffset",
    )
    replace_or_verify(schema / "CCSPlayerPawn.h", "FL_PAWN_FAKECLIENT", "FL_BOT")
    replace_or_verify(schema / "CCSPlayerController.h", "FL_CONTROLLER_FAKECLIENT", "FL_FAKECLIENT")
    ensure_timer_destructor(schema / "ctimer.h")
    ensure_noinline_pattern_scan(schema / "module.cpp", expected_count=2)
    if not (sdk_root / "public" / "tier1" / "generichash.h").is_file():
        raise SystemExit("pinned SDK is missing public/tier1/generichash.h")
    if (sdk_root / "tier1" / "generichash.cpp").exists():
        raise SystemExit("unexpected tier1/generichash.cpp exists in pinned SDK")
    print("SDK compatibility patches applied and validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
