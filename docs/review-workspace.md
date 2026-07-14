# Review Workspace

The review workspace is a read-only local web view bound to `127.0.0.1`.
It never promotes, edits, deletes, or uploads records.

## Reviewer operations

1. See candidate, failed, and verified counts at a glance.
2. Filter candidates by status and search by citation or source.
3. Inspect the exact quote, its stored prefix/suffix, snapshot hash, timestamps,
   and source integrity result.
4. See every promotion attempt and its explicit success/failure reason.
5. Confirm verified Evidence and the append-only promotion-chain position.
6. When a stack report is supplied, confirm the three-product result, event
   count, abbreviated revisions, and whether every checkout was clean.
7. When multiple reports are supplied, compare their verification time,
   trusted-head prefix, revisions, and changed-worktree warnings newest-first.
8. Select any of the eight visible runs to inspect its Evidence, Agent, and
   Ledger commit changes against the preceding run.
9. Confirm how many distinct trusted signers satisfied the configured quorum
   and, when configured, when that trust expires.
10. Open the same verified result from a single portable review bundle while
    keeping trusted key IDs outside that bundle.
11. Confirm completed and scheduled key rotations without exposing key IDs,
    public-key bytes, private keys, or local history paths.
12. When a pinned release index and matching archive-audit receipt are supplied,
    confirm the audited release range and package/signature counts without
    exposing index paths, receipt paths, or signer IDs.
13. When a pinned upgrade-history index and matching collection-audit receipt
    are supplied, confirm the continuous release range and verified transition
    count without exposing binding heads, paths, signer IDs, or claimed time.
14. When both inventory families are configured, confirm one combined result
    only after every archived release version and pack head matches one adjacent
    upgrade transition in the same order.
15. When a pinned workspace-acceptance receipt is supplied, show its bounded
    package/range/count projection without paths or key identities. If combined
    archive/upgrade coverage is also configured, require all four input heads,
    range, and counts to match before startup and add one compact receipt marker
    to the combined card.
16. When a pinned packet transition-history index and audit receipt are supplied,
    confirm their exact coverage binding before startup, compare the first and
    latest packet counts, and reveal full endpoint digests only on request.
17. When the current portable collection bundle is supplied with that history,
    require its bundle head and packet count to equal the latest history endpoint
    and show one combined current-record/history result.
18. When one pinned portable collection-lineage bundle is supplied, fully verify
    its embedded current collection and ordered transition collection before
    startup, then review the current records through the same combined result.

## States covered

- First run / empty workspace, loading, normal data, candidate only, failed
  promotion, verified Evidence, source missing/tampered, database error, and the
  bounded-result limit.
- Stack-report states cover not configured, verified with clean repositories,
  and verified with an explicit changed-repository warning. Invalid, oversized,
  or symbolic-link reports fail before the server starts.
- History is bounded to 20 reports, rejects duplicate trusted heads, and exposes
  neither report paths nor unknown fields. The compact timeline shows at most
  eight recent runs without adding page-level horizontal scrolling.
- Reports with JCS integrity show an explicit confirmation after digest
  verification. Legacy reports remain readable without making the stronger
  integrity claim.
- Valid detached signatures add a distinct-signer quorum confirmation. Missing,
  duplicate, invalid, untrusted, revoked, not-yet-valid, or expired trust never
  degrades to unsigned success when signature verification was requested.
- Portable bundles are regular files capped at 1 MiB and cannot be mixed with
  loose report/signature/key inputs. Embedded public keys are not trusted unless
  their SHA-256 IDs are supplied independently.
- A valid trust history replaces manual current-key and threshold input. Planned
  rotations show a reviewer-facing count; broken chains, unexpected signers,
  wrong anchors, and early activation fail before the workspace opens.
- Desktop uses a list/detail split. Mobile shows one hierarchy at a time and a
  clear back action. There is no horizontal scrolling.
- Keyboard focus is visible; filters, rows, and back navigation are keyboard
  reachable. All status text uses reviewer-facing Japanese labels.
- Archive inventory covers three explicit states: not configured teaches which
  artifacts to supply; a matching audit shows a compact success strip; partial,
  tampered, or mismatched input fails before the server starts. A runtime API
  failure renders a bounded error strip instead of silently hiding status.
- The inventory is read-only and has no destructive, paid, loading-form, or
  upgrade action. Desktop uses one horizontal summary; mobile wraps to a
  lead explanation plus two-column statistics with no horizontal scroll.
- Upgrade continuity has explicit loading, not-configured, verified, and runtime
  failure strips. Partial, tampered, rolled-back, or cross-linked input fails
  before startup; the verified strip states that its confirmation time is not
  independently attested.
- Exact combined coverage replaces the two verified inventory strips with one
  reviewer-facing summary. A middle-version mismatch, pack-head mismatch, or
  lagging history fails before startup. If the combined endpoint later becomes
  unavailable, individual success strips are removed and one explicit error
  strip is shown instead.
- Workspace acceptance receipt inputs are all-or-nothing. Receipt-only mode is
  explanatory; combined mode rejects any archive/audit head, range, or count
  mismatch before the local listener starts. The marker does not claim that the
  original package execution or archive evidence was replayed.
- Packet transition history has explicit unconfigured and verified views.
  Partial configuration, stale external heads, altered files, and a valid audit
  from another history fail before the listener starts. The verified card keeps
  long endpoint digests behind one disclosure control, exposes no paths or
  identities, and states that neither source artifacts nor time were reverified.
- A current collection bundle plus transition history is coherent only when both
  its bundle head and packet count equal the verified latest endpoint. A valid
  but older or unrelated bundle fails before listening. Success replaces the
  history-only wording with one combined card and keeps the full current bundle
  digest behind a 44px disclosure target.
- Portable lineage input is all-or-nothing and cannot be mixed with database,
  loose packet, collection-bundle, or loose transition-history inputs. Traversal,
  omission, duplication, reordering, cross-history substitution, and an older
  current endpoint fail before listening. Desktop and mobile reuse the current
  collection list and combined 44px disclosure card; the browser receives no
  lineage path, receipt contents, identity, or stronger trusted-time claim.

The browser receives only bounded review data. Source context is read locally,
rehash-verified, and returned as text; raw filesystem paths are not exposed.
