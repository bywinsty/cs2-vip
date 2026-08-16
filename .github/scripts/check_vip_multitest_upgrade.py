#!/usr/bin/env python3
"""Read-only upgrade preflight for the VIP_MultiTest namespace migration."""

import argparse
import sys
from pathlib import Path


LEGACY_PATHS = (
    Path("addons/vip_modules/vip_test.so"),
    Path("addons/metamod/vip_test.vdf"),
    Path("addons/configs/vip/vip_test.ini"),
)
CURRENT_PATHS = (
    Path("addons/vip_modules/vip_multitest.so"),
    Path("addons/metamod/vip_multitest.vdf"),
    Path("addons/configs/vip/vip_multitest.ini"),
)


def scan_installation(root):
    legacy = tuple(path for path in LEGACY_PATHS if (root / path).exists())
    current = tuple(path for path in CURRENT_PATHS if (root / path).exists())
    return legacy, current


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("installation_root", type=Path)
    args = parser.parse_args(argv)
    root = args.installation_root

    if not root.is_dir():
        print(f"installation root does not exist or is not a directory: {root}", file=sys.stderr)
        return 1

    legacy, current = scan_installation(root)
    if legacy:
        print("Legacy vip_test namespace detected; manual migration is required:")
        for path in legacy:
            print(f"  {path}")
        print("These files may belong to VIP_Test. Do not delete them automatically.")
        if current:
            print("New vip_multitest files are also present; verify the installation manually.")
        return 2

    print("VIP_MultiTest upgrade preflight passed: no legacy vip_test files detected.")
    if current:
        print("Current vip_multitest files detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
