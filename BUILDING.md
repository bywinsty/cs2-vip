# Reproducible Linux x86-64 build

The supported build environment is Ubuntu 24.04 with Python 3.12 and Clang 18.
CI is the executable reference for package validation; the commands below use
the same pinned dependency revisions and keep all dependency patches outside
the source checkout.

```bash
set -euo pipefail
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export VIP_DEPS_ROOT="$(mktemp -d)"
export VIP_EXTERNAL="$VIP_DEPS_ROOT/external"
export VIP_MANIFESTS="$VIP_DEPS_ROOT/hl2sdk-manifests"

git clone https://github.com/alliedmodders/ambuild.git "$VIP_DEPS_ROOT/ambuild"
git -C "$VIP_DEPS_ROOT/ambuild" checkout d89ec91a7ac2607da07b50bb62346f9a10e9a998
git clone https://github.com/alliedmodders/metamod-source.git "$VIP_EXTERNAL/metamod-source"
git -C "$VIP_EXTERNAL/metamod-source" checkout 2667e8e5947237c4cb7ea45cec3913ad6a44757c
git -C "$VIP_EXTERNAL/metamod-source" submodule update --init --recursive
git clone --branch cs2 https://github.com/alliedmodders/hl2sdk.git "$VIP_EXTERNAL/hl2sdk-cs2"
git -C "$VIP_EXTERNAL/hl2sdk-cs2" checkout 80cf8554d716a3841fe0680013cae3411a056a8d
git -C "$VIP_EXTERNAL/hl2sdk-cs2" submodule update --init --recursive
git clone https://github.com/pisex/SchemaEntity.git "$VIP_EXTERNAL/SchemaEntity"
git -C "$VIP_EXTERNAL/SchemaEntity" checkout e7965b3c83ec684d44584ee6457c5482ee5d9db1
cp -R "$VIP_EXTERNAL/metamod-source/hl2sdk-manifests" "$VIP_MANIFESTS"

python -m pip install --require-hashes -r .github/ci-requirements.txt
python -m pip install "$VIP_DEPS_ROOT/ambuild"
python .github/scripts/apply_sdk_compatibility_patches.py \
  --sdk-root "$VIP_EXTERNAL/hl2sdk-cs2" \
  --manifest-path "$VIP_MANIFESTS/manifests/cs2.json" \
  --schema-root "$VIP_EXTERNAL/SchemaEntity" \
  --require-include public/game/server

mkdir build && cd build
CC=clang-18 CXX=clang++-18 python ../configure.py \
  --sdks cs2 --targets x86_64 --enable-optimize --disable-debug \
  --hl2sdk-manifests="$VIP_MANIFESTS" \
  --mms_path="$VIP_EXTERNAL/metamod-source" \
  --hl2sdk-root="$VIP_EXTERNAL" \
  --schemaentity-root="$VIP_EXTERNAL/SchemaEntity"
ambuild
```

From the repository root, validate and package the result with:

```bash
python .github/scripts/verify_elf_hardening.py build/package/addons/vip/vip.so
python .github/scripts/create_reproducible_archive.py \
  --root build/package --output vip.zip --format zip
```

## Pin review

Pins were compared with their upstream branches on 2026-08-21. Metamod and
SchemaEntity were current. AMBuild was one commit ahead upstream and HL2SDK CS2
was fourteen commits ahead. They remain on the last fully qualified set because
dependency changes must be introduced one at a time and accepted only after the
complete build, package, ABI, reproducibility, and ELF gates pass.
