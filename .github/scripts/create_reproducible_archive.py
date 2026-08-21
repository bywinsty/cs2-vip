#!/usr/bin/env python3
"""Create a byte-reproducible ZIP or tar.gz from a directory tree."""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import stat
import tarfile
import time
import zipfile


def epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH")
    if not value or not value.isdigit():
        raise SystemExit("SOURCE_DATE_EPOCH must be a non-negative integer")
    return int(value)


def files(root: Path) -> list[Path]:
    return sorted((path for path in root.rglob("*") if path.is_file()), key=lambda p: p.relative_to(root).as_posix())


def mode(path: Path) -> int:
    return 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644


def create_zip(root: Path, output: Path, timestamp: int, prefix: str) -> None:
    zip_time = time.gmtime(max(timestamp, 315532800))[:6]
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files(root):
            relative = path.relative_to(root).as_posix()
            name = f"{prefix}/{relative}" if prefix else relative
            info = zipfile.ZipInfo(name, zip_time)
            info.create_system = 3
            info.external_attr = (mode(path) & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())


def create_tar_gz(root: Path, output: Path, timestamp: int, prefix: str) -> None:
    with output.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=timestamp, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in files(root):
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
    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit(f"archive root is not a directory: {root}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "zip":
        create_zip(root, args.output, epoch(), args.prefix.strip("/"))
    else:
        create_tar_gz(root, args.output, epoch(), args.prefix.strip("/"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
