# Contributing

Preserve the core invariant: an observation is never Evidence until the
promotion gate verifies its content-addressed source snapshot, exact citation
selector, and `availableAt`. Storage and portable artifacts remain local-first
and path-free at their public boundaries.

Before opening a pull request:

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm audit:secrets
```

Run `pnpm readiness:private` for release, packaging, dependency, SBOM, or
performance changes. Add focused regression tests for changed promotion,
storage-integrity, trust, or portable-artifact behavior. Use synthetic sources
only; never attach a real workspace, database, source snapshot, or signing key.
