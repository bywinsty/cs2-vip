# Runtime validation gate

The runtime gate is Linux x86-64 only and must run on a disposable CS2 dedicated server. It is deliberately not registered as a GitHub self-hosted runner.

## Mark the test server

Copy `.github/runtime-sentinel.example.json` to `<CS2_SERVER_ROOT>/.vip-ci-test-server`, then replace every placeholder with the exact installed versions and paths. The harness refuses to run when the sentinel is missing, malformed, marks the server as production, points outside the server root, lacks Metamod/runtime dependencies, finds an active server process, or has insufficient free disk space.

## Verify and run

First run the manual **Runtime Release Preflight** workflow for the `dev` tag. On the marked server:

```bash
export CS2_SERVER_ROOT=/srv/cs2-vip-ci
python3 .github/scripts/runtime_validate.py \
  --repository bywinsty/cs2-vip \
  --tag dev \
  --report-dir /var/tmp/cs2-vip-runtime-report
```

The harness downloads `vip.zip` and `vip.spdx.json`, verifies both GitHub attestations, checks the SBOM subject digest, installs a temporary overlay, starts CS2 in LAN/insecure mode on the configured map, executes `meta version` and `meta list`, checks all configured success markers, rejects crash/load/interface/unresolved-symbol markers, stops the server, and restores the previous files.

It always writes `runtime-validation.json` and `runtime-validation-logs.zip`. Preserve both even after a failed run.

## Stable release authorization

The `dev` prerelease remains automatic. A future `Core` stable release is blocked unless repository variables `RUNTIME_VALIDATION_SHA` and `RUNTIME_VALIDATION_REPORT_URL` identify a successful report for the exact stable commit. The report URL is included in the release notes. Do not set these variables until the JSON result is `success`, rollback is clean, and the log archive has been retained.
