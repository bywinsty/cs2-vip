#!/usr/bin/env python3
"""Fail-closed helpers for traversing release package trees."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import stat


class UnsafeTreeError(ValueError):
    pass


def is_link_like(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", lambda: False)
    return path.is_symlink() or bool(is_junction())


def collect_regular_files(root: Path) -> tuple[Path, list[Path]]:
    """Return a sorted, link-free set of regular files rooted at *root*."""
    if is_link_like(root):
        raise UnsafeTreeError(f"package root must not be a link or junction: {root}")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise UnsafeTreeError(f"package root cannot be resolved: {root}: {exc}") from exc
    if not resolved_root.is_dir():
        raise UnsafeTreeError(f"package root is not a directory: {resolved_root}")

    result: list[Path] = []
    for current_name, directory_names, file_names in os.walk(
        resolved_root, topdown=True, followlinks=False
    ):
        current = Path(current_name)
        for name in [*directory_names, *file_names]:
            candidate = current / name
            if is_link_like(candidate):
                raise UnsafeTreeError(f"links and junctions are forbidden in package trees: {candidate}")
        for name in file_names:
            candidate = current / name
            try:
                metadata = candidate.lstat()
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(resolved_root)
            except (OSError, ValueError) as exc:
                raise UnsafeTreeError(f"package path escapes or cannot be resolved: {candidate}") from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise UnsafeTreeError(f"package path is not a regular file: {candidate}")
            result.append(resolved)
    result.sort(key=lambda path: path.relative_to(resolved_root).as_posix())
    return resolved_root, result


def validate_archive_output(root: Path, output: Path) -> Path:
    """Resolve an archive output and reject aliases into the input tree."""
    if is_link_like(output):
        raise UnsafeTreeError(f"archive output must not be a link or junction: {output}")
    output = output.absolute()
    try:
        resolved_parent = output.parent.resolve(strict=False)
        resolved_output = resolved_parent / output.name
        resolved_output.relative_to(root.resolve(strict=True))
    except ValueError:
        output.parent.mkdir(parents=True, exist_ok=True)
        return output.parent.resolve(strict=True) / output.name
    except OSError as exc:
        raise UnsafeTreeError(f"archive output cannot be resolved: {output}: {exc}") from exc
    raise UnsafeTreeError(f"archive output must be outside package root: {resolved_output}")


def validate_archive_prefix(prefix: str) -> str:
    """Return a canonical relative POSIX archive prefix."""
    if prefix == "":
        return ""
    if "\\" in prefix or "\0" in prefix or re.match(r"^[A-Za-z]:", prefix):
        raise UnsafeTreeError(f"unsafe archive prefix: {prefix!r}")
    raw_parts = prefix.split("/")
    if prefix.startswith("/") or any(part in {"", ".", ".."} for part in raw_parts):
        raise UnsafeTreeError(f"unsafe archive prefix: {prefix!r}")
    parsed = PurePosixPath(prefix)
    if parsed.is_absolute() or parsed.parts != tuple(raw_parts):
        raise UnsafeTreeError(f"unsafe archive prefix: {prefix!r}")
    return prefix
