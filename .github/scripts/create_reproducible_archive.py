#!/usr/bin/env python3
"""Create a byte-reproducible ZIP or tar.gz from a directory tree."""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time
import zipfile

from safe_file_tree import (
    UnsafeTreeError,
    collect_regular_files,
    validate_archive_output,
    validate_archive_prefix,
)


def epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH")
    if not value or not value.isdigit():
        raise SystemExit("SOURCE_DATE_EPOCH must be a non-negative integer")
    return int(value)


def mode(path: Path) -> int:
    return 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644


def create_zip(root: Path, paths: list[Path], output: Path, timestamp: int, prefix: str) -> None:
    zip_time = time.gmtime(max(timestamp, 315532800))[:6]
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in paths:
            relative = path.relative_to(root).as_posix()
            name = f"{prefix}/{relative}" if prefix else relative
            info = zipfile.ZipInfo(name, zip_time)
            info.create_system = 3
            info.external_attr = (mode(path) & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())


def create_tar_gz(root: Path, paths: list[Path], output: Path, timestamp: int, prefix: str) -> None:
    with output.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=timestamp, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in paths:
                relative = path.relative_to(root).as_posix()
                name = f"{prefix}/{relative}" if prefix else relative
                info = archive.gettarinfo(str(path), arcname=name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = timestamp
                info.mode = mode(path)
                with path.open("rb") as source:
                    archive.addfile(info, source)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--format", choices=("zip", "tar.gz"), required=True)
    parser.add_argument("--prefix", default="")
    args = parser.parse_args()
    try:
        root, paths = collect_regular_files(args.root)
        output = validate_archive_output(root, args.output)
        prefix = validate_archive_prefix(args.prefix)
    except UnsafeTreeError as exc:
        raise SystemExit(f"archive creation refused: {exc}") from exc
    with tempfile.NamedTemporaryFile(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent, delete=False
    ) as temporary_handle:
        temporary = Path(temporary_handle.name)
    try:
        if args.format == "zip":
            create_zip(root, paths, temporary, epoch(), prefix)
        else:
            create_tar_gz(root, paths, temporary, epoch(), prefix)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
