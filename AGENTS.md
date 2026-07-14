# Agent guidance

- Preserve the invariant that an observation is never evidence until it passes the promotion gate.
- Keep source snapshots content-addressed and local by default.
- Evidence must retain its source snapshot hash, exact citation selector, and `availableAt`.
- Add regression tests for every promotion rule or storage-integrity change.
- Run `pnpm check` before completion.
