#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path


def main():
    paths = subprocess.check_output(["git", "ls-files", "-z"]).split(b"\0")
    bad = []
    for raw in paths:
        if not raw:
            continue
        name = os.fsdecode(raw)
        path = Path(name)
        try:
            data = subprocess.check_output(["git", "show", f":{name}"])
        except subprocess.CalledProcessError:
            data = path.read_bytes()
        if b"\0" in data:
            continue
        if b"\r" in data:
            bad.append(str(path))
    if bad:
        print("Files containing CR/CRLF line endings:", file=sys.stderr)
        print("\n".join(bad), file=sys.stderr)
        return 1
    print(f"LF check passed for {len(paths) - 1} tracked paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
