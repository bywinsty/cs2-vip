#!/usr/bin/env python3
"""Write a compact cache/toolchain telemetry record for CI artifacts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--output", required=True)
    record_parser.add_argument("--job", required=True)
    args = parser.parse_args()
    if args.command != "record":
        return 2
    keys = (
        "GITHUB_RUN_ID", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME",
        "RUNNER_OS", "RUNNER_ARCH", "SDK_CACHE_PRIMARY_KEY", "SDK_CACHE_MATCHED_KEY",
        "DEPENDENCY_CACHE_HIT", "DEPENDENCY_RESTORE_OUTCOME", "SDK_CACHE_SAVE_OUTCOME",
        "PIP_CACHE_PRIMARY_KEY", "PIP_CACHE_MATCHED_KEY", "PIP_CACHE_HIT",
        "PIP_RESTORE_OUTCOME", "PIP_CACHE_SAVE_OUTCOME", "SYSTEM_SETUP_SECONDS",
        "PYTHON_VERSION", "MISSING_APT_PACKAGES", "APT_UPDATED",
    )
    record = {"schema_version": 1, "job": args.job, **{key.lower(): os.getenv(key, "") for key in keys}}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
