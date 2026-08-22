# [VIP] CORE | LIST OF MODULES - [click](https://github.com/bywinsty/cs2-vip-modules)

## Requirements

- Counter-Strike 2 dedicated server and [Metamod:Source](https://www.sourcemm.net/)
- the Utils, Menus and Players providers from [cs2-menus](https://github.com/Pisex/cs2-menus)
- [sql_mm](https://github.com/zer0k-z/sql_mm); it is a mandatory external runtime dependency and is not included in the VIP archive
- database connection data configured in `addons/configs/databases.cfg`
- optional `ICookiesApi` provider; without it the local KeyValues backend remains available

The exact repositories, revisions, purposes and build/runtime/optional
classifications used for a release are recorded in
[`.github/dependency-manifest.json`](.github/dependency-manifest.json).

For crash diagnostics, install [Accelerator](https://github.com/komashchenko/AcceleratorLocal/releases/tag/v1.0.0) and send the generated crash file.

## Release archive

The archive contains:
```text
addons/
├── metamod/vip.vdf
├── vip/vip.so
├── configs/databases.cfg
├── configs/vip/groups.ini
├── translations/vip.phrases.txt
└── data/vip_data.ini
```

## Commands
Client command:

- `!vip` - plugin main menu

Console commands:
- `vip_reload` - reload VIP configuration with groups
- `vip_remove <userid|nickname|accountid>` - remove VIP access from a player
- `vip_give <userid|nickname|accountid> <time_second> <group>` - give VIP access to a player

`vip_runtime_probe <32-hex-nonce>` is an internal, server-console-only CI
command. It is not an administrative or client command. When the database is
ready, it writes nonce-bound evidence under `addons/data` for the protected
CSHOST runtime-validation workflow.

## Configuration
- Database file: `addons/configs/databases.cfg`
- Groups file: `addons/configs/vip/groups.ini`
- Translation file: `addons/translations/vip.phrases.txt`

## Account ID migration

VIP persistence uses SteamID64. Supported database targets are MariaDB
10.3.38 for compatibility with the current hosting environment, MariaDB
10.11.x LTS and MySQL 8.4.x LTS. MariaDB 10.3 is end-of-life and should be
[upgraded by the hosting administrator](https://mariadb.org/about/);
compatibility here is not a security or maintenance guarantee for that database
series.

Create and verify a database backup before every upgrade. Startup keeps the
VIP API unavailable while a resumable migration runs under a database-specific
advisory lock. The migration:

1. creates `vip_schema_migrations` and the idempotent
   `vip_users_migration_conflicts` archive;
2. safely widens signed 32-bit IDs and normalizes negative legacy values;
3. resolves duplicate representations (an existing SteamID64 row wins over a
   legacy row; between two legacy forms, the positive account ID wins);
4. archives every losing row before deletion, converts valid account IDs to
   SteamID64 and verifies the result;
5. finalizes `account_id` as `BIGINT UNSIGNED` and only then makes the VIP API
   ready.

Values `0` and unknown large values are preserved with a warning rather than
silently rewritten. A SQL error records the failing stage and leaves
`VIP_IsVIPLoaded()` false. Correct the database or connection problem, inspect
the conflict archive, and restart: completed stages are designed to be safe to
run again. Do not manually mark a migration complete. Restore the verified
backup if the data policy cannot be resolved safely.

The local KeyValues backend also converts legacy account IDs. Numeric values
passed to administrative commands must be complete unsigned decimal values;
zero, signs, whitespace, trailing characters and overflow are rejected without
throwing an exception.

## Supply-chain metadata

Every release archive has an [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/)
SBOM generated from the canonical dependency manifest. Relationships point
from each dependency to the release
and use `BUILD_TOOL_OF`, `BUILD_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF`,
`PROVIDED_DEPENDENCY_OF` or `OPTIONAL_DEPENDENCY_OF` as appropriate. CI rejects
unknown, missing, duplicated or reclassified dependencies and rejects a
manifest that attempts to authorize those changes by itself.

The SDK compatibility patcher is tested against source, already-patched and
invalid mixed states. CI runs it twice and compares the complete patched SDK
trees byte-for-byte; the second run must make no change.

Public `IVIPApi001` and `IVIPApi002` factory names and layouts remain unchanged.
Database state, build metadata and the runtime probe are internal additions.

## Runtime validation and promotion

GitHub Actions release builds embed the exact source commit in `vip.so` through
`VIP_BUILD_COMMIT`; local builds are marked `local`. The manually dispatched
`CSHOST Runtime Validation` workflow accepts only the current `Core` tip and a
successful push build of that same commit. It overlays only
`addons/vip/vip.so` on a dedicated non-production test server, checks A2S,
database readiness, both public ABI factories, migration schema and pinned
runtime dependencies, then restores the original binary and server state.

The validation produces a custom runtime attestation bound to the SHA-256 of
`vip.zip`. Promotion refuses to move the `Core` tag unless that attestation was
issued by the pinned validation workflow for the same commit/build/artifact,
records a successful rollback and is no older than 24 hours.

An operator can verify the downloaded candidate's runtime signature and pinned
signer before inspecting the JSON predicate:

```bash
gh attestation verify vip.zip \
  --repo bywinsty/cs2-vip \
  --predicate-type https://github.com/bywinsty/cs2-vip/runtime-validation/v3 \
  --signer-workflow bywinsty/cs2-vip/.github/workflows/cshost-runtime-validation.yml \
  --format json
```

The protected environment, sentinel, restricted FTP account and recovery
procedure are documented in [`.github/CSHOST_RUNTIME.md`](.github/CSHOST_RUNTIME.md).

## Pull-request checks and branch protection

Pull requests targeting `dev`, `PR` or `Core` run the GitHub merge ref through
the release build, unit/contract tests and the full database migration matrix.
The workflows intentionally do not use `pull_request_target`, so untrusted PR
code does not execute with target-branch privileges or secrets.

The canonical required-check and review policy is documented in
[`.github/BRANCH_PROTECTION.md`](.github/BRANCH_PROTECTION.md). Apply it only
after the merged workflows have produced every named check at least once.
Required checks remain pending when GitHub's commit-message skip syntax is
used, so it cannot create a successful bypass on protected branches.
