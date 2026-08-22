#!/usr/bin/env python3
"""Print a deterministic byte-level digest manifest for one or more trees."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("roots", nargs="+", type=Path)
    args = parser.parse_args()
    excluded = set(args.exclude)
    entries: list[str] = []
    for index, raw_root in enumerate(args.roots):
        root = raw_root.resolve(strict=True)
        if not root.is_dir():
            raise SystemExit(f"tree root is not a directory: {root}")
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            relative = path.relative_to(root)
            if any(part in excluded for part in relative.parts):
                continue
            label = f"{index}:{root.name}/{relative.as_posix()}"
            if path.is_symlink():
                target = os.readlink(path)
                entries.append(f"LINK {hashlib.sha256(target.encode()).hexdigest()} {label}")
            elif path.is_file():
                entries.append(f"FILE {digest(path)} {label}")
    print("\n".join(entries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
