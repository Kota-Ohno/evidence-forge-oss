import { chmod, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import type { EvidenceCandidate, WebSourceCapture } from "./domain.js";
import { captureLocalCitation } from "./forge.js";
import {
  LocalWorkspace,
  MAX_QUERY_LIMIT,
  MAX_RECORD_BYTES,
  WORKSPACE_SCHEMA_VERSION,
} from "./workspace.js";

const roots: string[] = [];
const AVAILABLE_AT = "2026-07-11T00:00:00.000Z";
const OBSERVED_AT = new Date("2026-07-11T01:00:00.000Z");
const VERIFIED_AT = new Date("2026-07-11T02:00:00.000Z");

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture(label = "first"): Promise<{
  root: string;
  databasePath: string;
  candidate: EvidenceCandidate;
}> {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-workspace-"));
  roots.push(root);
  const sourcePath = join(root, `${label}.txt`);
  const exact = `Verified ${label} fact.`;
  await writeFile(sourcePath, `Alpha. ${exact} Omega.`);
  const candidate = await captureLocalCitation({
    workspace: join(root, "objects"),
    sourcePath,
    exact,
    availableAt: AVAILABLE_AT,
    now: () => OBSERVED_AT,
  });
  return { root, databasePath: join(root, "workspace.sqlite"), candidate };
}

function webCapture(candidate: EvidenceCandidate): WebSourceCapture {
  const snapshot = {
    ...candidate.snapshot,
    sourceUri: "https://example.com/final",
    capturedAt: candidate.observedAt,
    availableAt: candidate.observedAt,
  };
  return {
    kind: "WebSourceCapture",
    id: `web_${candidate.id}`,
    snapshot,
    wireResponse: {
      sha256: snapshot.sha256,
      byteLength: snapshot.byteLength,
      objectPath: snapshot.objectPath,
      contentEncoding: "identity",
    },
    requestedUrl: "https://example.com/start",
    canonicalUrl: "https://example.com/final",
    redirectChain: [{ url: "https://example.com/start", status: 302, location: "/final" }],
    status: 200,
    representationHeaders: { "content-type": "text/plain; charset=utf-8" },
    retrievedAt: snapshot.capturedAt,
    availableAt: snapshot.availableAt,
    availabilityBasis: "successful-http-response-completed",
  };
}

describe("LocalWorkspace", () => {
  it("migrates a fresh database and persists candidates without creating evidence", async () => {
    const { databasePath, candidate } = await fixture();
    const workspace = new LocalWorkspace(databasePath);

    expect(workspace.schemaVersion).toBe(WORKSPACE_SCHEMA_VERSION);
    workspace.saveCandidate(candidate, OBSERVED_AT);
    expect(workspace.getCandidate(candidate.id)).toEqual(candidate);
    expect(workspace.getSnapshotsByHash(candidate.snapshot.sha256)).toEqual([candidate.snapshot]);
    expect(workspace.listPromotions()).toEqual([]);
    expect(workspace.getEvidence("evidence_missing")).toBeUndefined();
    workspace.close();
    expect((await stat(databasePath)).mode & 0o777).toBe(0o600);
  });

  it("atomically persists verified evidence and hash-linked promotion history", async () => {
    const first = await fixture("first");
    const secondRoot = first.root;
    const secondSource = join(secondRoot, "second.txt");
    await writeFile(secondSource, "Alpha. Verified second fact. Omega.");
    const second = await captureLocalCitation({
      workspace: join(secondRoot, "objects"), sourcePath: secondSource,
      exact: "Verified second fact.", availableAt: AVAILABLE_AT, now: () => OBSERVED_AT,
    });
    const workspace = new LocalWorkspace(first.databasePath);

    const firstEvidence = await workspace.promoteAndPersist(first.candidate, () => VERIFIED_AT);
    const secondEvidence = await workspace.promoteAndPersist(second, () => VERIFIED_AT);
    const promotions = workspace.listPromotions();
    expect(workspace.getEvidence(firstEvidence.id)).toEqual(firstEvidence);
    expect(workspace.getEvidence(secondEvidence.id)).toEqual(secondEvidence);
    expect(promotions).toHaveLength(2);
    expect(promotions[0]?.previousRecordSha256).toBeNull();
    expect(promotions[1]?.previousRecordSha256).toBe(promotions[0]?.recordSha256);
    workspace.close();

    const reopened = new LocalWorkspace(first.databasePath);
    expect(reopened.getEvidence(firstEvidence.id)).toEqual(firstEvidence);
    expect(reopened.listPromotions()).toEqual(promotions);
    reopened.close();
  });

  it("rolls back Evidence when promotion-history insertion fails", async () => {
    const { databasePath, candidate } = await fixture();
    new LocalWorkspace(databasePath).close();
    const raw = new DatabaseSync(databasePath);
    raw.exec(`
      CREATE TRIGGER test_fail_history BEFORE INSERT ON promotion_history
      BEGIN SELECT RAISE(ABORT, 'injected history failure'); END;
    `);
    raw.close();

    const workspace = new LocalWorkspace(databasePath);
    await expect(workspace.promoteAndPersist(candidate, () => VERIFIED_AT))
      .rejects.toThrow("injected history failure");
    expect(workspace.listPromotions()).toEqual([]);
    expect(workspace.getCandidate(candidate.id)).toEqual(candidate);
    workspace.close();

    const inspect = new DatabaseSync(databasePath);
    expect(inspect.prepare("SELECT count(*) AS count FROM verified_evidence").get())
      .toEqual({ count: 0 });
    inspect.close();
  });

  it("persists a malformed candidate but never promotes it without passing the gate", async () => {
    const { databasePath, candidate } = await fixture();
    const malformed = {
      ...candidate,
      selector: { ...candidate.selector, prefix: "forged" },
    };
    const workspace = new LocalWorkspace(databasePath);
    workspace.saveCandidate(malformed, OBSERVED_AT);

    await expect(workspace.promoteAndPersist(malformed, () => VERIFIED_AT))
      .rejects.toMatchObject({ code: "SELECTOR_CONTEXT_MISMATCH" });
    expect(workspace.getCandidate(candidate.id)).toEqual(malformed);
    expect(workspace.listPromotions()).toEqual([]);
    workspace.close();
  });

  it("recovers by rolling back an interrupted transaction", async () => {
    const { databasePath, candidate } = await fixture();
    new LocalWorkspace(databasePath).close();
    const raw = new DatabaseSync(databasePath);
    raw.exec("PRAGMA foreign_keys = ON; BEGIN IMMEDIATE");
    raw.prepare(`
      INSERT INTO source_snapshots(snapshot_ref, sha256, available_at, captured_at, record_json)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      "snapshot_interrupted", candidate.snapshot.sha256, candidate.snapshot.availableAt,
      candidate.snapshot.capturedAt, JSON.stringify(candidate.snapshot),
    );
    raw.close();

    const recovered = new LocalWorkspace(databasePath);
    expect(recovered.getSnapshotsByHash(candidate.snapshot.sha256)).toEqual([]);
    recovered.close();
  });

  it("enforces append-only promotion history in the database", async () => {
    const { databasePath, candidate } = await fixture();
    const workspace = new LocalWorkspace(databasePath);
    await workspace.promoteAndPersist(candidate, () => VERIFIED_AT);
    workspace.close();

    const raw = new DatabaseSync(databasePath);
    expect(() => { raw.exec("UPDATE promotion_history SET promoted_at = 'forged'"); })
      .toThrow("promotion history is append-only");
    expect(() => { raw.exec("DELETE FROM promotion_history"); })
      .toThrow("promotion history is append-only");
    raw.close();
  });

  it("detects promotion-history tampering when records are queried", async () => {
    const { databasePath, candidate } = await fixture();
    const workspace = new LocalWorkspace(databasePath);
    await workspace.promoteAndPersist(candidate, () => VERIFIED_AT);
    workspace.close();

    const raw = new DatabaseSync(databasePath);
    raw.exec("DROP TRIGGER promotion_history_no_update");
    raw.exec("UPDATE promotion_history SET record_json = json_set(record_json, '$.promotedAt', 'forged')");
    raw.close();
    const reopened = new LocalWorkspace(databasePath);
    expect(() => reopened.listPromotions()).toThrow("integrity failure");
    reopened.close();
  });

  it("rejects unknown fields in stored candidate and Evidence envelopes", async () => {
    const { databasePath, candidate } = await fixture();
    const workspace = new LocalWorkspace(databasePath);
    const evidence = await workspace.promoteAndPersist(candidate, () => VERIFIED_AT);
    workspace.close();

    const raw = new DatabaseSync(databasePath);
    raw.exec("UPDATE candidates SET record_json = json_set(record_json, '$.localPath', '/private/input')");
    raw.exec("UPDATE verified_evidence SET record_json = json_set(record_json, '$.candidateId', 'candidate_other')");
    raw.close();

    const reopened = new LocalWorkspace(databasePath);
    expect(() => reopened.getCandidate(candidate.id)).toThrow("Evidence envelope is invalid");
    expect(() => reopened.getEvidence(evidence.id)).toThrow("Evidence envelope is invalid");
    expect(() => reopened.listReviewItems()).toThrow("Evidence envelope is invalid");
    reopened.close();
  });

  it("fails closed on a future schema version", async () => {
    const { databasePath } = await fixture();
    const raw = new DatabaseSync(databasePath);
    raw.exec(`PRAGMA user_version = ${String(WORKSPACE_SCHEMA_VERSION + 1)}`);
    raw.close();
    expect(() => new LocalWorkspace(databasePath)).toThrow("newer than supported");
  });

  it("migrates an existing version 1 workspace without changing prior records", async () => {
    const { databasePath, candidate } = await fixture();
    const initial = new LocalWorkspace(databasePath);
    const evidence = await initial.promoteAndPersist(candidate, () => VERIFIED_AT);
    const promotions = initial.listPromotions();
    initial.close();
    const raw = new DatabaseSync(databasePath);
    raw.exec("DROP TABLE promotion_attempts; DROP TABLE web_source_captures; PRAGMA user_version = 1");
    raw.close();

    const migrated = new LocalWorkspace(databasePath);
    expect(migrated.schemaVersion).toBe(3);
    expect(migrated.getCandidate(candidate.id)).toEqual(candidate);
    expect(migrated.getEvidence(evidence.id)).toEqual(evidence);
    expect(migrated.listPromotions()).toEqual(promotions);
    expect(migrated.getWebCapture("web_capture_missing")).toBeUndefined();
    const capture = webCapture(candidate);
    migrated.saveWebCapture(capture, VERIFIED_AT);
    expect(migrated.getWebCapture(capture.id)).toEqual(capture);
    const webCandidate = { ...candidate, id: `${candidate.id}_web`, snapshot: capture.snapshot };
    migrated.saveCandidate(webCandidate, VERIFIED_AT);
    expect(migrated.getWebCapturesForCandidate(webCandidate.id)).toEqual([capture]);
    migrated.close();
  });

  it("enforces immutable web capture records in the database", async () => {
    const { databasePath, candidate } = await fixture();
    const capture = webCapture(candidate);
    const workspace = new LocalWorkspace(databasePath);
    workspace.saveWebCapture(capture, OBSERVED_AT);
    workspace.close();

    const raw = new DatabaseSync(databasePath);
    expect(() => { raw.exec("UPDATE web_source_captures SET canonical_url = 'https://attacker.invalid'"); })
      .toThrow("web source captures are immutable");
    expect(() => { raw.exec("DELETE FROM web_source_captures"); })
      .toThrow("web source captures are immutable");
    raw.close();
    const reopened = new LocalWorkspace(databasePath);
    expect(reopened.getWebCapture(capture.id)).toEqual(capture);
    reopened.close();
  });

  it("refuses a symlink database path without touching its target", async () => {
    const { root } = await fixture();
    const target = join(root, "unrelated-target");
    const link = join(root, "workspace-link.sqlite");
    const original = "must remain untouched";
    await writeFile(target, original);
    await chmod(target, 0o644);
    await symlink(target, link);

    expect(() => new LocalWorkspace(link)).toThrow("must not be a symbolic link");
    expect(await readFile(target, "utf8")).toBe(original);
    expect((await stat(target)).mode & 0o777).toBe(0o644);
  });

  it("rolls back a failed migration without advancing the schema version", async () => {
    const { databasePath } = await fixture();
    const raw = new DatabaseSync(databasePath);
    raw.exec("CREATE TABLE source_snapshots(conflict TEXT) STRICT");
    raw.close();

    expect(() => new LocalWorkspace(databasePath)).toThrow("already exists");
    const inspect = new DatabaseSync(databasePath);
    expect(inspect.prepare("PRAGMA user_version").get()).toEqual({ user_version: 0 });
    expect(inspect.prepare(`
      SELECT count(*) AS count FROM sqlite_schema WHERE type = 'table' AND name = 'candidates'
    `).get()).toEqual({ count: 0 });
    inspect.close();
  });

  it("rejects conflicting immutable records and bounded-input violations", async () => {
    const { databasePath, candidate } = await fixture();
    const workspace = new LocalWorkspace(databasePath);
    workspace.saveCandidate(candidate, OBSERVED_AT);
    workspace.saveCandidate(candidate, OBSERVED_AT);
    expect(() => { workspace.saveCandidate({
      ...candidate,
      selector: { ...candidate.selector, prefix: "forged" },
    }, OBSERVED_AT); }).toThrow("Conflicting immutable candidates record");
    expect(() => workspace.getCandidate("x".repeat(257))).toThrow("1 to 256");
    expect(() => workspace.listPromotions(MAX_QUERY_LIMIT + 1)).toThrow("limit");
    expect(() => { workspace.saveCandidate({
      ...candidate,
      selector: { ...candidate.selector, exact: "x".repeat(MAX_RECORD_BYTES) },
    }, OBSERVED_AT); }).toThrow("exceeds");
    workspace.close();
  });
});
