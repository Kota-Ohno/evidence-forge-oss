# Local SQLite workspace

M3 uses Node 24's built-in `node:sqlite` module. It adds no runtime database
dependency and keeps all records on the user's machine.
The implementation targets Node 24.4 or newer; see the
[official Node SQLite documentation](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html).

## Durability and recovery

- File-backed databases use WAL mode, `synchronous=FULL`, foreign keys, a five
  second busy timeout, and explicit `BEGIN IMMEDIATE` transactions.
- Candidate persistence is separate from promotion. Saving an observation or
  candidate never creates Evidence.
- The existing promotion gate runs before Evidence persistence. The Evidence row
  and promotion-history row are then committed atomically.
- Promotion history is hash-linked and has database triggers that reject UPDATE
  and DELETE operations. Queries recompute and verify the chain before returning
  records.
- Every open runs SQLite `quick_check`; unsupported future schema versions fail
  closed.

## Schema lifecycle

`PRAGMA user_version` is the authoritative schema version. Migrations run inside
an explicit transaction and only advance the version after their statements
succeed. The current version is `2`. Version 2 adds immutable raw web capture
records linked to source snapshots. Saving one does not create a candidate or
Evidence row.

## Bounds and privacy

Serialized records are capped at 1 MiB, identifiers at 256 characters, and query
limits at 1,000 rows. Workspace directories and database files are created with
owner-only permissions. Source content remains in the existing content-addressed
object store; SQLite records references and domain metadata, not duplicate source
bytes.
