# CSHOST runtime validation

This gate is for a dedicated disposable test server only. It must never target
a production server or a server with players. The workflow is manual and runs
only for the current `Core` tip.

## One-time GitHub setup

Create the protected environment `cshost-runtime-test` in repository settings.
Configure at least one required reviewer and prevent administrators from
bypassing the protection. Enable prevention of self-review. The workflow reads
the environment metadata and fails if any of these controls is absent. Store
these environment secrets:

- `CSHOST_API_BASE`: HTTPS API v2 endpoint without a query string, for example
  the provider's `/api2` endpoint;
- `CSHOST_API_TOKEN`: a per-server token for the test server;
- `CSHOST_FTP_HOST`, `CSHOST_FTP_PORT`, `CSHOST_FTP_USER`,
  `CSHOST_FTP_PASSWORD`, `CSHOST_FTP_ROOT`;
- `CSHOST_SENTINEL_SHA256`: lowercase SHA-256 of the exact sentinel bytes on
  the server.

Use a separate FTP account restricted to the test-server root. The account
needs access only to the public plugin binary, `.vip-ci` journal/backups and
`addons/data/vip-runtime-validation-*.json`. Do not grant access to unrelated
servers. GitHub-hosted runners use plain FTP because that is the provider
interface assumed by this workflow; therefore never transfer database dumps,
`databases.cfg`, other configuration, tokens or personal data through it.

The validation job receives the CSHOST environment secrets but has no
`id-token` or write permission. A separate job receives no CSHOST secrets and
is the only job allowed to create the custom attestation.

## Test-server sentinel

Copy `.github/cshost-runtime-sentinel.example.json`, replace every placeholder,
and upload the result as `.vip-ci/runtime-sentinel-v3.json` relative to
`CSHOST_FTP_ROOT`. Keep these invariants:

- `purpose` is exactly `vip-ci-test-server` and `production` is `false`;
- `stage_id` is SHA-256 of an opaque, stable test-stage identifier, not a host,
  customer or account name;
- `plugin_path` and `evidence_directory` remain fixed;
- A2S points to the same test server;
- required capabilities are Metamod, Utils, Menus, Players, SQLMM; Cookies is
  optional;
- every dependency contains the deployed version, exact `.so` path and
  lowercase SHA-256.

Hash the exact uploaded bytes and store that digest in
`CSHOST_SENTINEL_SHA256`. Any edit then deliberately blocks validation until
the protected secret is reviewed and updated.

The server must use an isolated test database. Back it up before the first
migration test. Configurations and user data are never uploaded or downloaded
by the workflow.

## Validation run

1. Wait for a successful `Build AMBuild Plugin` push run on the current `Core`
   commit and note its numeric run ID.
2. Open `CSHOST Runtime Validation`, choose branch `Core`, mode `validate`, and
   supply that build run ID.
3. The required reviewer verifies that the target is the isolated empty test
   stage and approves the environment deployment.
4. Download the diagnostic report if the job fails. Do not promote until a
   successful runtime attestation exists.

Preflight rejects a changed sentinel, unavailable API/FTP, players, an
incorrect artifact/build commit or dependency hash. The candidate is downloaded
from the verified build run and only `addons/vip/vip.so` is extracted. Before
the overlay, the validator records the original state and SHA-256 in a durable
remote journal. Successful validation requires A2S app ID 730, nonce-bound
probe evidence, `IVIPApi001` and `IVIPApi002`, `ready=true`, migration state
`ready`, `BIGINT UNSIGNED`, and verified runtime dependency hashes.

Rollback is mandatory on success and failure. The workflow stops the candidate,
restores the original binary and original online/offline state, verifies the
restored SHA-256, removes evidence, and only then permits attestation.

## Recovery

Never delete `.vip-ci/runtime-overlay-journal-v3.json` or its referenced backup
manually. Every new run first restores an unfinished journal. If a normal run
cannot complete, dispatch the workflow on `Core` with mode `restore-only`; no
build run ID is required. It restores only when the currently installed binary
matches either the recorded original or candidate digest. An unknown binary is
left untouched and requires manual investigation.

After recovery, verify the server state and original `vip.so` SHA-256 from the
diagnostic report before starting another validation.

## Promotion policy

`Promote Core Stable Release` verifies the runtime attestation locally with
GitHub CLI JSON output. The signer workflow, signer/source commit, `Core` ref,
predicate type, archive/binary hashes, build run ID, probe result, dependency
set, rollback and 24-hour maximum age are all fail-closed checks. The mutable
report URL and caller-supplied runtime digest are not trusted. Tag movement is
after this verification step.
