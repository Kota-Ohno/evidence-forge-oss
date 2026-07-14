## Summary

Describe the operator-visible outcome and the invariant it preserves.

## Verification

- [ ] `pnpm check`
- [ ] Focused tests cover changed behavior
- [ ] `pnpm audit:secrets` for release-related changes
- [ ] `pnpm readiness:private` for packaging, supply-chain, or performance changes

## Evidence and release boundary

- [ ] Observations and Candidates are not represented as Evidence before promotion
- [ ] No real source content, prompts, credentials, paths, databases, or private keys were added
- [ ] Portable outputs retain their closed, path-free assurance limits
- [ ] This PR does not make anything public or publish a package
