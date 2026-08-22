# Branch protection rollout

The canonical policy is stored in [branch-protection.json](branch-protection.json)
and validated by `test_branch_protection.py`. It protects `Core`, `PR` and `dev`,
requires build, unit and migration-matrix checks, dismisses stale approvals,
requires approval after the last push, applies to administrators and forbids
force pushes and deletion.

Do not apply the policy before all named checks have completed successfully at
least once on GitHub. Requiring a context that GitHub has not observed can lock
the branch against normal merges.

After the workflows have been merged and have produced all required contexts:

```bash
python .github/scripts/configure_branch_protection.py
python .github/scripts/configure_branch_protection.py --apply
```

The first command is a read-only dry run. The second requires an authenticated
GitHub CLI identity with repository administration permission. Verify all three
branches after application:

```bash
gh api repos/bywinsty/cs2-vip/branches/Core/protection
gh api repos/bywinsty/cs2-vip/branches/PR/protection
gh api repos/bywinsty/cs2-vip/branches/dev/protection
```

The repository policy does not create environments or runners. Create
`cshost-runtime-test` with at least one required reviewer, `prevent_self_review`
enabled and administrator bypass disabled. Register an ephemeral runner group
with labels `self-hosted,cshost-runtime,ephemeral`; do not permit PR workflows
to use it. Verify the complete operational state with:

```bash
python .github/scripts/verify_github_gates.py --repository bywinsty/cs2-vip
```

The runtime gate remains blocked until this verifier passes and a disposable
stage has completed `restore-only` successfully.

GitHub-recognized commit-message skip instructions are not reimplemented in
the workflows. If one is used, the associated required check remains pending,
so the protected branch cannot be merged through that route.
