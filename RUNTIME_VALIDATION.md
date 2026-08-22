# Runtime validation gate

The runtime gate is Linux x86-64 only and must run on a disposable CS2 dedicated server with a test database. It is deliberately not registered as a GitHub self-hosted runner.

## Mark and pin the test server

Copy `.github/runtime-sentinel.example.json` to `<CS2_SERVER_ROOT>/.vip-ci-test-server`. Replace the example build ID, dependency versions, SHA-256 values, paths, A2S endpoint, and map with the exact installed values.

Only `schema_version: 2` is accepted. The harness fails closed for a malformed or production sentinel, placeholders, duplicate dependencies, links or paths outside the server root, a different CS2 build, dependency hash mismatch, an active server process, or insufficient disk space.

## Validate an Actions candidate

After the `PR` push workflow and its candidate-attestation job are green, run on the marked server:

```bash
export CS2_SERVER_ROOT=/srv/cs2-vip-ci
python3 .github/scripts/runtime_validate.py \
  --repository bywinsty/cs2-vip \
  --run-id <PR_BUILD_RUN_ID> \
  --expected-commit <PR_COMMIT_SHA> \
  --report-dir /var/tmp/cs2-vip-runtime-report
```

`--run-id` accepts only a successful push run for `PR` or `Core` whose `headSha` equals `--expected-commit`. For release diagnostics, use `--tag dev|Core`; for an already downloaded pair, use `--artifact-dir PATH`. These sources are mutually exclusive, and a full run always requires the expected commit.

The harness requires exactly `vip.zip` and `vip.spdx.json`. It verifies ZIP provenance, the ZIP's SPDX 2.3 predicate, SPDX-document provenance, the SPDX subject name/digest/commit, CS2 build ID, and pinned runtime dependency hashes and versions.

During startup the harness supplies a random nonce to an opt-in core probe. Success requires unique nonce-bound JSON events proving both `IVIPApi` and `IVIPApi002`, database setup and `SetReady(true)`. It independently sends an A2S_INFO query, including challenge-response handling, and requires an exact map match. Crash, load, interface, and unresolved-symbol markers remain fail-fast errors, not positive readiness evidence.

## Transactional overlay and reports

The overlay is installed with same-directory temporary files and atomic replacement. Before every target mutation, `overlay-journal.json` records the relative path, original and candidate SHA-256, prior existence, and backup path. Backups and the journal live in `--report-dir`, outside both the server root and temporary extraction directories.

Rollback verifies the final state of every file and is safe to repeat. If automatic restoration fails, the report, journal, and backups are retained and the command exits nonzero. Retry separately with:

```bash
python3 .github/scripts/runtime_validate.py \
  --restore-journal /var/tmp/cs2-vip-runtime-report/overlay-journal.json
```

The harness always writes a `runtime-validation-v2` JSON report plus `runtime-validation-logs.zip`. A full result is `success` only when artifact, preflight, runtime evidence, A2S, shutdown, and verified rollback all succeed. Preserve both outputs; preserve the journal and backup whenever recovery fails.

## Stable promotion after merge

The `dev` prerelease remains automatic. A `Core` push builds and attests a candidate but never publishes stable automatically.

After merging `PR` into `Core`, repeat the runtime gate with the successful `Core` push run and the actual post-merge Core SHA. Store the successful evidence URL, set repository variables `RUNTIME_VALIDATION_SHA` and `RUNTIME_VALIDATION_REPORT_URL`, then manually run **Promote verified Core release** with that Core build run ID. Promotion verifies the current Core tip, run metadata, runtime variables, exact attested artifact, and byte equality after release upload.

The separate `cs2-vip-modules` runtime gate for all 35 modules is not covered by this core report and remains mandatory before a complete ecosystem rollout.
