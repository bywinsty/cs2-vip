"""Verify the pinned Python packaging toolchain used by CI."""

from __future__ import annotations

import argparse
import sys


EXPECTED_PYTHON = (3, 12)
EXPECTED_SETUPTOOLS = "68.1.2"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-ambuild",
        action="store_true",
        help="also import the AMBuild 2 API used by module configure scripts",
    )
    args = parser.parse_args()

    if sys.version_info[:2] != EXPECTED_PYTHON:
        raise SystemExit(
            f"Expected Python {EXPECTED_PYTHON[0]}.{EXPECTED_PYTHON[1]}, "
            f"got {sys.version_info.major}.{sys.version_info.minor}"
        )

    import setuptools

    if setuptools.__version__ != EXPECTED_SETUPTOOLS:
        raise SystemExit(
            f"Expected setuptools {EXPECTED_SETUPTOOLS}, "
            f"got {setuptools.__version__}"
        )

    try:
        from distutils import core as distutils_core
    except Exception as exc:  # pragma: no cover - exercised on the CI runner
        raise SystemExit(
            "The pinned setuptools version cannot provide the distutils compatibility "
            f"layer: {exc}"
        ) from exc

    print(f"Python: {sys.version.split()[0]}")
    print(f"setuptools: {setuptools.__version__}")
    print(f"distutils: {distutils_core.__file__}")

    if args.check_ambuild:
        from ambuild2 import run, util

        print(f"AMBuild API: {getattr(run, 'CURRENT_API', 'unknown')}")
        print(f"AMBuild utilities: {util.__file__}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
