#!/usr/bin/env python3
"""Apply and validate the pinned CS2 SDK compatibility adjustments."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def _ensure_include(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if '#include "gametrace.h"' in text:
        return
    needle = '#include "schemasystem.h"\n'
    if needle not in text:
        raise SystemExit(f"expected schemasystem include not found: {path}")
    _write(path, text.replace(needle, needle + '#include "gametrace.h"\n', 1))


def _replace_or_verify(path: Path, old: str, new: str, description: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old in text:
        _write(path, text.replace(old, new))
        return
    if new not in text:
        raise SystemExit(f"{description}: expected source pattern not found in {path}")


def _ensure_timer_destructor(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if "virtual ~CTimerBase()" in text:
        return
    needle = "class CTimerBase {\npublic:\n"
    if needle not in text:
        raise SystemExit(f"CTimerBase declaration not found: {path}")
    _write(path, text.replace(needle, needle + "    virtual ~CTimerBase() = default;\n", 1))


def _patch_proto(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    syntax = [line.strip() for line in text.splitlines() if line.strip().startswith("syntax = ")]
    if not syntax:
        _write(path, 'syntax = "proto2";\n' + text)
    elif syntax != ['syntax = "proto2";']:
        raise SystemExit(f"unsupported protobuf syntax in {path}: {syntax}")


def _patch_manifest(path: Path, sdk_root: Path, required_includes: list[str]) -> None:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    original = manifest.get("include_paths")
    if not isinstance(original, list):
        raise SystemExit(f"manifest include_paths is not a list: {path}")
    filtered = [item for item in original if isinstance(item, str) and (sdk_root / item).is_dir()]
    for required in required_includes:
        if (sdk_root / required).is_dir() and required not in filtered:
            raise SystemExit(f"required manifest include is missing: {required}")
    if filtered != original:
        manifest["include_paths"] = filtered
        _write(path, json.dumps(manifest, indent=4) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--proto-path", type=Path)
    parser.add_argument("--manifest-path", type=Path)
    parser.add_argument("--schema-root", type=Path)
    parser.add_argument("--require-include", action="append", default=[])
    args = parser.parse_args()

    sdk_root = args.sdk_root
    proto_path = args.proto_path or sdk_root / "common" / "network_connection.proto"
    _patch_proto(proto_path)

    if args.manifest_path:
        _patch_manifest(args.manifest_path, sdk_root, args.require_include)

    if args.schema_root:
        schema = args.schema_root
        _ensure_include(schema / "globaltypes.h")
        _replace_or_verify(
            schema / "schemasystem.cpp",
            "NetworkStateChanged_t",
            "NetworkStateChangedData",
            "network state type compatibility patch",
        )
        for filename, old, new in (
            ("CCSPlayerPawn.h", "FL_PAWN_FAKECLIENT", "FL_BOT"),
            ("CCSPlayerController.h", "FL_CONTROLLER_FAKECLIENT", "FL_FAKECLIENT"),
        ):
            _replace_or_verify(schema / filename, old, new, "fake-client flag compatibility patch")
        _ensure_timer_destructor(schema / "ctimer.h")

    if not (sdk_root / "public" / "tier1" / "generichash.h").is_file():
        raise SystemExit("pinned SDK is missing public/tier1/generichash.h")
    if (sdk_root / "tier1" / "generichash.cpp").exists():
        raise SystemExit("unexpected tier1/generichash.cpp exists in pinned SDK")

    print("SDK compatibility patches applied and validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
