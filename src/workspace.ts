import { randomUUID } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { isDeepStrictEqual } from "node:util";
import type { EvidenceCandidate, SourceSnapshot, VerifiedEvidence, WebSourceCapture } from "./domain.js";
import { assertEvidenceCandidate, assertSourceSnapshot, assertVerifiedEvidence } from "./evidence-envelope.js";
import { assertWebSourceCapture } from "./web-capture.js";
import { promoteCandidate } from "./forge.js";
import { PromotionError } from "./domain.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { parseTimestamp } from "./timestamp.js";

export const WORKSPACE_SCHEMA_VERSION = 4;
export const MAX_RECORD_BYTES = 1_048_576;
export const MAX_QUERY_LIMIT = 1_000;

export interface PromotionRecord {
  readonly sequence: number;
  readonly candidateId: string;
  readonly evidenceId: string;
  readonly snapshotRef: string;
  readonly promotedAt: string;
  readonly previousRecordSha256: string | null;
  readonly recordSha256: string;
}

export interface PromotionAttempt {
  readonly sequence: number;
  readonly attemptId: string;
  readonly candidateId: string;
  readonly attemptedAt: string;
  readonly outcome: "verified" | "rejected";
  readonly failureCode: string | null;
  readonly failureMessage: string | null;
}

export interface ReviewItem {
  readonly candidate: EvidenceCandidate;
  readonly evidence?: VerifiedEvidence;
  readonly latestAttempt?: PromotionAttempt;
  readonly promotion?: PromotionRecord;
  readonly status: "candidate" | "rejected" | "verified";
}

export interface ReviewListItem {
  readonly id: string;
  readonly status: "candidate" | "rejected" | "verified";
  readonly quote: string;
  readonly quoteTruncated: boolean;
  readonly prefix: string;
  readonly suffix: string;
  readonly observedAt: string;
  readonly availableAt: string;
  readonly capturedAt: string;
  readonly sha256: string;
  readonly byteLength: number;
  readonly mediaType: string;
  readonly sourceUri: string;
  readonly failureCode: string | null;
  readonly failureMessage: string | null;
}

interface PromotionRecordPayload {
  readonly candidateId: string;
  readonly evidenceId: string;
  readonly snapshotRef: string;
  readonly promotedAt: string;
  readonly previousRecordSha256: string | null;
}

interface JsonRow {
  readonly record_json: string;
}

interface VersionRow {
  readonly user_version: number;
}

interface PromotionRow {
  readonly sequence: number;
  readonly candidate_id: string;
  readonly evidence_id: string;
  readonly snapshot_ref: string;
  readonly promoted_at: string;
  readonly previous_record_sha256: string | null;
  readonly record_sha256: string;
  readonly record_json: string;
}

const MIGRATION_1 = `
  CREATE TABLE source_snapshots (
    snapshot_ref TEXT PRIMARY KEY CHECK(length(snapshot_ref) BETWEEN 10 AND 80),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    available_at TEXT NOT NULL CHECK(length(available_at) BETWEEN 10 AND 64),
    captured_at TEXT NOT NULL CHECK(length(captured_at) BETWEEN 10 AND 64),
    record_json TEXT NOT NULL CHECK(length(record_json) <= ${String(MAX_RECORD_BYTES)}) CHECK(json_valid(record_json))
  ) STRICT;
  CREATE INDEX source_snapshots_sha256 ON source_snapshots(sha256);

  CREATE TABLE candidates (
    candidate_id TEXT PRIMARY KEY CHECK(length(candidate_id) BETWEEN 1 AND 256),
    snapshot_ref TEXT NOT NULL REFERENCES source_snapshots(snapshot_ref),
    observed_at TEXT NOT NULL CHECK(length(observed_at) BETWEEN 10 AND 64),
    record_json TEXT NOT NULL CHECK(length(record_json) <= ${String(MAX_RECORD_BYTES)}) CHECK(json_valid(record_json)),
    persisted_at TEXT NOT NULL CHECK(length(persisted_at) BETWEEN 20 AND 32)
  ) STRICT;

  CREATE TABLE verified_evidence (
    evidence_id TEXT PRIMARY KEY CHECK(length(evidence_id) BETWEEN 1 AND 256),
    candidate_id TEXT NOT NULL UNIQUE REFERENCES candidates(candidate_id),
    snapshot_ref TEXT NOT NULL REFERENCES source_snapshots(snapshot_ref),
    verified_at TEXT NOT NULL CHECK(length(verified_at) BETWEEN 20 AND 32),
    record_json TEXT NOT NULL CHECK(length(record_json) <= ${String(MAX_RECORD_BYTES)}) CHECK(json_valid(record_json))
  ) STRICT;

  CREATE TABLE promotion_history (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT NOT NULL UNIQUE REFERENCES candidates(candidate_id),
    evidence_id TEXT NOT NULL UNIQUE REFERENCES verified_evidence(evidence_id),
    snapshot_ref TEXT NOT NULL REFERENCES source_snapshots(snapshot_ref),
    promoted_at TEXT NOT NULL CHECK(length(promoted_at) BETWEEN 20 AND 32),
    previous_record_sha256 TEXT CHECK(previous_record_sha256 IS NULL OR length(previous_record_sha256) = 64),
    record_sha256 TEXT NOT NULL UNIQUE CHECK(length(record_sha256) = 64),
    record_json TEXT NOT NULL CHECK(length(record_json) <= ${String(MAX_RECORD_BYTES)}) CHECK(json_valid(record_json))
  ) STRICT;

  CREATE TRIGGER promotion_history_no_update
  BEFORE UPDATE ON promotion_history
  BEGIN SELECT RAISE(ABORT, 'promotion history is append-only'); END;

  CREATE TRIGGER promotion_history_no_delete
  BEFORE DELETE ON promotion_history
  BEGIN SELECT RAISE(ABORT, 'promotion history is append-only'); END;
`;

const MIGRATION_2 = `
  CREATE TABLE web_source_captures (
    capture_id TEXT PRIMARY KEY CHECK(length(capture_id) BETWEEN 1 AND 256),
    snapshot_ref TEXT NOT NULL REFERENCES source_snapshots(snapshot_ref),
    requested_url TEXT NOT NULL CHECK(length(requested_url) BETWEEN 8 AND 8192),
    canonical_url TEXT NOT NULL CHECK(length(canonical_url) BETWEEN 8 AND 8192),
    retrieved_at TEXT NOT NULL CHECK(length(retrieved_at) BETWEEN 20 AND 32),
    record_json TEXT NOT NULL CHECK(length(record_json) <= ${String(MAX_RECORD_BYTES)}) CHECK(json_valid(record_json)),
    persisted_at TEXT NOT NULL CHECK(length(persisted_at) BETWEEN 20 AND 32)
  ) STRICT;
  CREATE INDEX web_source_captures_snapshot ON web_source_captures(snapshot_ref);

  CREATE TRIGGER web_source_captures_no_update
  BEFORE UPDATE ON web_source_captures
  BEGIN SELECT RAISE(ABORT, 'web source captures are immutable'); END;

  CREATE TRIGGER web_source_captures_no_delete
  BEFORE DELETE ON web_source_captures
  BEGIN SELECT RAISE(ABORT, 'web source captures are immutable'); END;
`;

const MIGRATION_3 = `
  CREATE TABLE promotion_attempts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id TEXT NOT NULL UNIQUE CHECK(length(attempt_id) BETWEEN 10 AND 256),
    candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id),
    attempted_at TEXT NOT NULL CHECK(length(attempted_at) BETWEEN 20 AND 32),
    outcome TEXT NOT NULL CHECK(outcome IN ('verified', 'rejected')),
    failure_code TEXT CHECK(failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128),
    failure_message TEXT CHECK(failure_message IS NULL OR length(failure_message) BETWEEN 1 AND 512),
    CHECK(
      (outcome = 'verified' AND failure_code IS NULL AND failure_message IS NULL) OR
      (outcome = 'rejected' AND failure_code IS NOT NULL AND failure_message IS NOT NULL)
    )
  ) STRICT;
  CREATE INDEX promotion_attempts_candidate ON promotion_attempts(candidate_id, sequence DESC);

  CREATE TRIGGER promotion_attempts_no_update
  BEFORE UPDATE ON promotion_attempts
  BEGIN SELECT RAISE(ABORT, 'promotion attempts are append-only'); END;

  CREATE TRIGGER promotion_attempts_no_delete
  BEFORE DELETE ON promotion_attempts
  BEGIN SELECT RAISE(ABORT, 'promotion attempts are append-only'); END;
`;

const MIGRATION_4 = `
  CREATE TABLE candidate_review_summaries (
    candidate_id TEXT PRIMARY KEY REFERENCES candidates(candidate_id),
    quote TEXT NOT NULL CHECK(length(CAST(quote AS BLOB)) BETWEEN 1 AND 960),
    quote_truncated INTEGER NOT NULL CHECK(quote_truncated IN (0, 1)),
    prefix TEXT NOT NULL CHECK(length(CAST(prefix AS BLOB)) <= 128),
    suffix TEXT NOT NULL CHECK(length(CAST(suffix AS BLOB)) <= 128),
    observed_at TEXT NOT NULL CHECK(length(observed_at) BETWEEN 20 AND 64),
    available_at TEXT NOT NULL CHECK(length(available_at) BETWEEN 20 AND 64),
    captured_at TEXT NOT NULL CHECK(length(captured_at) BETWEEN 20 AND 64),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 0 AND 16777216),
    media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 256),
    source_uri TEXT NOT NULL CHECK(length(source_uri) BETWEEN 1 AND 4096)
  ) STRICT;

  CREATE TRIGGER candidate_review_summaries_no_update
  BEFORE UPDATE ON candidate_review_summaries
  BEGIN SELECT RAISE(ABORT, 'candidate review summaries are immutable'); END;

  CREATE TRIGGER candidate_review_summaries_no_delete
  BEFORE DELETE ON candidate_review_summaries
  BEGIN SELECT RAISE(ABORT, 'candidate review summaries are immutable'); END;

  CREATE TRIGGER source_snapshots_no_update BEFORE UPDATE ON source_snapshots
  BEGIN SELECT RAISE(ABORT, 'source snapshots are immutable'); END;
  CREATE TRIGGER source_snapshots_no_delete BEFORE DELETE ON source_snapshots
  BEGIN SELECT RAISE(ABORT, 'source snapshots are immutable'); END;
  CREATE TRIGGER candidates_no_update BEFORE UPDATE ON candidates
  BEGIN SELECT RAISE(ABORT, 'candidates are immutable'); END;
  CREATE TRIGGER candidates_no_delete BEFORE DELETE ON candidates
  BEGIN SELECT RAISE(ABORT, 'candidates are immutable'); END;
  CREATE TRIGGER verified_evidence_no_update BEFORE UPDATE ON verified_evidence
  BEGIN SELECT RAISE(ABORT, 'verified evidence is immutable'); END;
  CREATE TRIGGER verified_evidence_no_delete BEFORE DELETE ON verified_evidence
  BEGIN SELECT RAISE(ABORT, 'verified evidence is immutable'); END;
`;

export class LocalWorkspace {
  readonly #database: DatabaseSync;

  constructor(readonly path: string) {
    if (path !== ":memory:") {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      refuseSymbolicLink(path);
    }
    this.#database = new DatabaseSync(path, { timeout: 5_000 });
    if (path !== ":memory:") chmodSync(path, 0o600);
    this.#database.exec("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA busy_timeout = 5000;");
    if (path !== ":memory:") {
      this.#database.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
    }
    try {
      this.#migrate();
      const integrity = this.#database.prepare("PRAGMA quick_check").get() as { quick_check: string };
      if (integrity.quick_check !== "ok") throw new Error(`Workspace integrity check failed: ${integrity.quick_check}`);
    } catch (error) {
      if (this.#database.isOpen) this.#database.close();
      throw error;
    }
  }

  close(): void {
    this.#database.close();
  }

  get schemaVersion(): number {
    return this.#version();
  }

  saveCandidate(candidate: EvidenceCandidate | VerifiedEvidence, persistedAt = new Date()): void {
    if (candidate.kind !== "EvidenceCandidate") throw new TypeError("Only EvidenceCandidate can be persisted as a candidate");
    assertEvidenceCandidate(candidate);
    assertDate(persistedAt, "persistedAt");
    const candidateJson = boundedJson(candidate, "candidate");
    const snapshotJson = boundedJson(candidate.snapshot, "snapshot");
    const snapshotRef = snapshotReference(candidate.snapshot);

    this.#transaction(() => {
      this.#database.prepare(`
        INSERT INTO source_snapshots(snapshot_ref, sha256, available_at, captured_at, record_json)
        VALUES (?, ?, ?, ?, ?) ON CONFLICT(snapshot_ref) DO NOTHING
      `).run(snapshotRef, candidate.snapshot.sha256, candidate.snapshot.availableAt, candidate.snapshot.capturedAt, snapshotJson);
      assertStoredJson(this.#database, "source_snapshots", "snapshot_ref", snapshotRef, snapshotJson);

      this.#database.prepare(`
        INSERT INTO candidates(candidate_id, snapshot_ref, observed_at, record_json, persisted_at)
        VALUES (?, ?, ?, ?, ?) ON CONFLICT(candidate_id) DO NOTHING
      `).run(candidate.id, snapshotRef, candidate.observedAt, candidateJson, persistedAt.toISOString());
      assertStoredJson(this.#database, "candidates", "candidate_id", candidate.id, candidateJson);
      insertReviewSummary(this.#database, candidate);
    });
  }

  saveWebCapture(capture: WebSourceCapture, persistedAt = new Date()): void {
    assertWebSourceCapture(capture);
    if (
      capture.availableAt !== capture.retrievedAt ||
      capture.snapshot.availableAt !== capture.availableAt ||
      capture.snapshot.capturedAt !== capture.retrievedAt ||
      capture.snapshot.sourceUri !== capture.canonicalUrl ||
      (capture as { availabilityBasis?: unknown }).availabilityBasis !== "successful-http-response-completed"
    ) {
      throw new TypeError("Web capture availability and canonical snapshot metadata are inconsistent");
    }
    assertDate(persistedAt, "persistedAt");
    assertIdentifier(capture.id, "capture id");
    const captureJson = boundedJson(capture, "web capture");
    const snapshotJson = boundedJson(capture.snapshot, "snapshot");
    const snapshotRef = snapshotReference(capture.snapshot);
    this.#transaction(() => {
      this.#database.prepare(`
        INSERT INTO source_snapshots(snapshot_ref, sha256, available_at, captured_at, record_json)
        VALUES (?, ?, ?, ?, ?) ON CONFLICT(snapshot_ref) DO NOTHING
      `).run(snapshotRef, capture.snapshot.sha256, capture.snapshot.availableAt, capture.snapshot.capturedAt, snapshotJson);
      assertStoredJson(this.#database, "source_snapshots", "snapshot_ref", snapshotRef, snapshotJson);
      this.#database.prepare(`
        INSERT INTO web_source_captures(
          capture_id, snapshot_ref, requested_url, canonical_url, retrieved_at, record_json, persisted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(capture_id) DO NOTHING
      `).run(capture.id, snapshotRef, capture.requestedUrl, capture.canonicalUrl, capture.retrievedAt, captureJson, persistedAt.toISOString());
      assertStoredJson(this.#database, "web_source_captures", "capture_id", capture.id, captureJson);
    });
  }

  getWebCapture(id: string): WebSourceCapture | undefined {
    assertIdentifier(id, "capture id");
    return parseRecord<WebSourceCapture>(
      this.#database.prepare("SELECT record_json FROM web_source_captures WHERE capture_id = ?").get(id) as JsonRow | undefined,
      "WebSourceCapture",
    );
  }

  getWebCapturesForCandidate(candidateId: string, limit = 2): WebSourceCapture[] {
    assertIdentifier(candidateId, "candidate id");
    assertLimit(limit);
    const rows = this.#database.prepare(`
      SELECT w.record_json
      FROM candidates c
      JOIN web_source_captures w ON w.snapshot_ref = c.snapshot_ref
      WHERE c.candidate_id = ?
      ORDER BY w.persisted_at, w.capture_id LIMIT ?
    `).all(candidateId, limit) as unknown as JsonRow[];
    return rows.map((row) => parseRecord<WebSourceCapture>(row, "WebSourceCapture") as WebSourceCapture);
  }

  async promoteAndPersist(
    candidate: EvidenceCandidate,
    now: () => Date = () => new Date(),
  ): Promise<VerifiedEvidence> {
    const attemptedAt = now();
    this.saveCandidate(candidate, attemptedAt);
    let evidence: VerifiedEvidence;
    try {
      evidence = await promoteCandidate(candidate, () => attemptedAt);
    } catch (error) {
      const failureCode = error instanceof PromotionError ? error.code : "UNEXPECTED_ERROR";
      const failureMessage = error instanceof PromotionError ? error.message : "Promotion failed unexpectedly";
      this.#recordAttempt(candidate.id, attemptedAt, "rejected", failureCode, failureMessage);
      throw error;
    }
    assertVerifiedEvidence(evidence);
    const evidenceJson = boundedJson(evidence, "verified evidence");
    const snapshotRef = snapshotReference(evidence.snapshot);

    this.#transaction(() => {
      this.#database.prepare(`
        INSERT INTO verified_evidence(evidence_id, candidate_id, snapshot_ref, verified_at, record_json)
        VALUES (?, ?, ?, ?, ?)
      `).run(evidence.id, evidence.candidateId, snapshotRef, evidence.verifiedAt, evidenceJson);

      const previous = this.#database.prepare(`
        SELECT record_sha256 FROM promotion_history ORDER BY sequence DESC LIMIT 1
      `).get() as { record_sha256: string } | undefined;
      const payload: PromotionRecordPayload = {
        candidateId: evidence.candidateId,
        evidenceId: evidence.id,
        snapshotRef,
        promotedAt: evidence.verifiedAt,
        previousRecordSha256: previous?.record_sha256 ?? null,
      };
      const recordJson = boundedJson(payload, "promotion record");
      const recordSha256 = canonicalJsonSha256(payload);
      this.#database.prepare(`
        INSERT INTO promotion_history(
          candidate_id, evidence_id, snapshot_ref, promoted_at,
          previous_record_sha256, record_sha256, record_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        payload.candidateId, payload.evidenceId, payload.snapshotRef, payload.promotedAt,
        payload.previousRecordSha256, recordSha256, recordJson,
      );
      this.#insertAttempt(candidate.id, attemptedAt, "verified", null, null);
    });
    return evidence;
  }

  listPromotionAttempts(candidateId: string, limit = 100): PromotionAttempt[] {
    assertIdentifier(candidateId, "candidate id");
    assertLimit(limit);
    return (this.#database.prepare(`
      SELECT sequence, attempt_id, candidate_id, attempted_at, outcome, failure_code, failure_message
      FROM promotion_attempts WHERE candidate_id = ? ORDER BY sequence DESC LIMIT ?
    `).all(candidateId, limit) as unknown as Array<Record<string, unknown>>).map(toPromotionAttempt);
  }

  listReviewItems(limit = 200): ReviewItem[] {
    assertLimit(limit);
    const rows = this.#database.prepare(`
      SELECT c.record_json AS candidate_json, e.record_json AS evidence_json,
             c.candidate_id AS candidate_row_id, e.evidence_id AS evidence_row_id,
             e.candidate_id AS evidence_candidate_row_id,
             p.sequence AS promotion_sequence, p.evidence_id, p.snapshot_ref,
             p.promoted_at, p.previous_record_sha256, p.record_sha256,
             a.sequence AS attempt_sequence, a.attempt_id, a.attempted_at,
             a.outcome AS attempt_outcome, a.failure_code, a.failure_message
      FROM candidates c
      LEFT JOIN verified_evidence e ON e.candidate_id = c.candidate_id
      LEFT JOIN promotion_history p ON p.candidate_id = c.candidate_id
      LEFT JOIN promotion_attempts a ON a.sequence = (
        SELECT sequence FROM promotion_attempts
        WHERE candidate_id = c.candidate_id ORDER BY sequence DESC LIMIT 1
      )
      ORDER BY c.persisted_at DESC, c.candidate_id LIMIT ?
    `).all(limit) as unknown as Array<Record<string, unknown>>;
    return rows.map(toReviewItem);
  }

  listReviewSummaries(limit = 200): ReviewListItem[] {
    assertLimit(limit);
    const rows = this.#database.prepare(`
      SELECT s.candidate_id AS candidate_row_id, s.quote, s.quote_truncated, s.prefix, s.suffix,
             s.observed_at, s.available_at, s.captured_at, s.sha256, s.byte_length,
             s.media_type, s.source_uri, e.evidence_id, p.evidence_id AS promotion_evidence_id,
             a.outcome AS attempt_outcome, a.failure_code, a.failure_message
      FROM candidate_review_summaries s
      JOIN candidates c ON c.candidate_id = s.candidate_id
      LEFT JOIN verified_evidence e ON e.candidate_id = s.candidate_id
      LEFT JOIN promotion_history p ON p.candidate_id = s.candidate_id AND p.evidence_id = e.evidence_id
      LEFT JOIN promotion_attempts a ON a.sequence = (
        SELECT sequence FROM promotion_attempts
        WHERE candidate_id = s.candidate_id ORDER BY sequence DESC LIMIT 1
      )
      ORDER BY c.persisted_at DESC, s.candidate_id LIMIT ?
    `).all(limit) as unknown as Array<Record<string, unknown>>;
    return rows.map(toReviewListItem);
  }

  getReviewItem(candidateId: string): ReviewItem | undefined {
    assertIdentifier(candidateId, "candidate id");
    const row = this.#database.prepare(`
      SELECT c.record_json AS candidate_json, e.record_json AS evidence_json,
             c.candidate_id AS candidate_row_id, e.evidence_id AS evidence_row_id,
             e.candidate_id AS evidence_candidate_row_id,
             p.sequence AS promotion_sequence, p.evidence_id, p.snapshot_ref,
             p.promoted_at, p.previous_record_sha256, p.record_sha256,
             a.sequence AS attempt_sequence, a.attempt_id, a.attempted_at,
             a.outcome AS attempt_outcome, a.failure_code, a.failure_message
      FROM candidates c
      LEFT JOIN verified_evidence e ON e.candidate_id = c.candidate_id
      LEFT JOIN promotion_history p ON p.candidate_id = c.candidate_id
      LEFT JOIN promotion_attempts a ON a.sequence = (
        SELECT sequence FROM promotion_attempts
        WHERE candidate_id = c.candidate_id ORDER BY sequence DESC LIMIT 1
      )
      WHERE c.candidate_id = ?
    `).get(candidateId) as unknown as Record<string, unknown> | undefined;
    return row === undefined ? undefined : toReviewItem(row);
  }

  getCandidate(id: string): EvidenceCandidate | undefined {
    assertIdentifier(id, "candidate id");
    return parseRecord<EvidenceCandidate>(
      this.#database.prepare("SELECT record_json FROM candidates WHERE candidate_id = ?").get(id) as JsonRow | undefined,
      "EvidenceCandidate", id,
    );
  }

  getEvidence(id: string): VerifiedEvidence | undefined {
    assertIdentifier(id, "evidence id");
    const row = this.#database.prepare(`
      SELECT e.record_json, e.candidate_id, c.record_json AS candidate_json
      FROM verified_evidence e JOIN candidates c ON c.candidate_id = e.candidate_id
      WHERE e.evidence_id = ?
    `).get(id) as unknown as (JsonRow & { candidate_id: string; candidate_json: string }) | undefined;
    if (!row) return undefined;
    const evidence = parseRecord<VerifiedEvidence>(row, "VerifiedEvidence", id);
    if (!evidence) return undefined;
    const candidate = parseJson(row.candidate_json);
    assertEvidenceCandidate(candidate);
    if (candidate.id !== row.candidate_id) invalidStoredEnvelope();
    assertEvidenceBinding(evidence, candidate);
    return evidence;
  }

  getSnapshotsByHash(sha256: string, limit = 100): SourceSnapshot[] {
    if (!/^[0-9a-f]{64}$/u.test(sha256)) throw new RangeError("snapshot sha256 must be 64 lowercase hexadecimal characters");
    assertLimit(limit);
    const rows = this.#database.prepare(`
      SELECT record_json FROM source_snapshots WHERE sha256 = ? ORDER BY captured_at LIMIT ?
    `).all(sha256, limit) as unknown as JsonRow[];
    return rows.map((row) => {
      const snapshot = parseJson(row.record_json);
      assertSourceSnapshot(snapshot);
      return snapshot;
    });
  }

  listPromotions(limit = 100): PromotionRecord[] {
    assertLimit(limit);
    const rows = this.#database.prepare(`
      SELECT sequence, candidate_id, evidence_id, snapshot_ref, promoted_at,
             previous_record_sha256, record_sha256, record_json
      FROM promotion_history ORDER BY sequence LIMIT ?
    `).all(limit) as unknown as PromotionRow[];
    verifyPromotionRows(rows);
    return rows.map((row) => ({
      sequence: row.sequence,
      candidateId: row.candidate_id,
      evidenceId: row.evidence_id,
      snapshotRef: row.snapshot_ref,
      promotedAt: row.promoted_at,
      previousRecordSha256: row.previous_record_sha256,
      recordSha256: row.record_sha256,
    }));
  }

  #migrate(): void {
    const version = this.#version();
    if (version > WORKSPACE_SCHEMA_VERSION) {
      this.#database.close();
      throw new Error(`Workspace schema ${String(version)} is newer than supported ${String(WORKSPACE_SCHEMA_VERSION)}`);
    }
    if (version === 0) {
      this.#transaction(() => {
        this.#database.exec(MIGRATION_1);
        this.#database.exec("PRAGMA user_version = 1");
      });
    }
    if (this.#version() === 1) {
      this.#transaction(() => {
        this.#database.exec(MIGRATION_2);
        this.#database.exec("PRAGMA user_version = 2");
      });
    }
    if (this.#version() === 2) {
      this.#transaction(() => {
        this.#database.exec(MIGRATION_3);
        this.#database.exec("PRAGMA user_version = 3");
      });
    }
    if (this.#version() === 3) {
      this.#transaction(() => {
        this.#database.exec(MIGRATION_4);
        const rows = this.#database.prepare("SELECT record_json FROM candidates ORDER BY candidate_id").all() as unknown as JsonRow[];
        for (const row of rows) {
          const candidate = parseRecord<EvidenceCandidate>(row, "EvidenceCandidate");
          if (!candidate) invalidStoredEnvelope();
          insertReviewSummary(this.#database, candidate);
        }
        this.#database.exec("PRAGMA user_version = 4");
      });
    }
  }

  #version(): number {
    return (this.#database.prepare("PRAGMA user_version").get() as unknown as VersionRow).user_version;
  }

  #transaction<T>(operation: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      if (this.#database.isTransaction) this.#database.exec("ROLLBACK");
      throw error;
    }
  }

  #recordAttempt(candidateId: string, attemptedAt: Date, outcome: "rejected", code: string, message: string): void {
    this.#transaction(() => { this.#insertAttempt(candidateId, attemptedAt, outcome, code, message); });
  }

  #insertAttempt(candidateId: string, attemptedAt: Date, outcome: "verified" | "rejected", code: string | null, message: string | null): void {
    this.#database.prepare(`
      INSERT INTO promotion_attempts(attempt_id, candidate_id, attempted_at, outcome, failure_code, failure_message)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(`attempt_${randomUUID()}`, candidateId, attemptedAt.toISOString(), outcome, code, message);
  }
}

function toPromotionAttempt(row: Record<string, unknown>): PromotionAttempt {
  return {
    sequence: Number(row.sequence), attemptId: String(row.attempt_id), candidateId: String(row.candidate_id),
    attemptedAt: String(row.attempted_at), outcome: row.outcome === "verified" ? "verified" : "rejected",
    failureCode: row.failure_code === null ? null : databaseString(row.failure_code, "failure_code"),
    failureMessage: row.failure_message === null ? null : databaseString(row.failure_message, "failure_message"),
  };
}

function toReviewItem(row: Record<string, unknown>): ReviewItem {
  const candidate = parseJson(String(row.candidate_json));
  assertEvidenceCandidate(candidate);
  if (candidate.id !== row.candidate_row_id) invalidStoredEnvelope();
  const evidence = row.evidence_json === null
    ? undefined
    : parseJson(databaseString(row.evidence_json, "evidence_json"));
  if (evidence !== undefined) {
    assertVerifiedEvidence(evidence);
    if (evidence.id !== row.evidence_row_id || evidence.candidateId !== row.evidence_candidate_row_id) {
      invalidStoredEnvelope();
    }
    assertEvidenceBinding(evidence, candidate);
  }
  const latestAttempt = row.attempt_sequence === null ? undefined : toPromotionAttempt({
    sequence: row.attempt_sequence, attempt_id: row.attempt_id, candidate_id: candidate.id,
    attempted_at: row.attempted_at, outcome: row.attempt_outcome,
    failure_code: row.failure_code, failure_message: row.failure_message,
  });
  const promotion = row.promotion_sequence === null ? undefined : {
    sequence: Number(row.promotion_sequence), candidateId: candidate.id,
    evidenceId: String(row.evidence_id), snapshotRef: String(row.snapshot_ref),
    promotedAt: String(row.promoted_at),
    previousRecordSha256: row.previous_record_sha256 === null
      ? null
      : databaseString(row.previous_record_sha256, "previous_record_sha256"),
    recordSha256: String(row.record_sha256),
  } satisfies PromotionRecord;
  return {
    candidate, ...(evidence ? { evidence } : {}), ...(latestAttempt ? { latestAttempt } : {}),
    ...(promotion ? { promotion } : {}),
    status: evidence ? "verified" : latestAttempt?.outcome === "rejected" ? "rejected" : "candidate",
  };
}

function toReviewListItem(row: Record<string, unknown>): ReviewListItem {
  const id = databaseString(row.candidate_row_id, "candidate_row_id");
  assertIdentifier(id, "candidate id");
  const quote = boundedDatabaseCharacters(row.quote, "quote", 240);
  if (quote.length === 0) invalidStoredEnvelope();
  const quoteTruncated = row.quote_truncated === 1 ? true : row.quote_truncated === 0 ? false : invalidStoredEnvelope();
  const prefix = boundedDatabaseCharacters(row.prefix, "prefix", 32);
  const suffix = boundedDatabaseCharacters(row.suffix, "suffix", 32);
  const observedAt = timestampDatabaseString(row.observed_at, "observed_at");
  const availableAt = timestampDatabaseString(row.available_at, "available_at");
  const capturedAt = timestampDatabaseString(row.captured_at, "captured_at");
  if (parseTimestamp(availableAt) > parseTimestamp(capturedAt) ||
      parseTimestamp(capturedAt) > parseTimestamp(observedAt)) invalidStoredEnvelope();
  const sha256 = databaseString(row.sha256, "sha256");
  if (!/^[0-9a-f]{64}$/u.test(sha256)) invalidStoredEnvelope();
  const byteLength = Number(row.byte_length);
  if (!Number.isSafeInteger(byteLength) || byteLength < 0 || byteLength > 16 * 1024 * 1024) invalidStoredEnvelope();
  const mediaType = boundedDatabaseString(row.media_type, "media_type", 256, false);
  const sourceUri = boundedDatabaseString(row.source_uri, "source_uri", 4096, false);
  const failureCode = nullableDatabaseString(row.failure_code, "failure_code", 128);
  const failureMessage = nullableDatabaseString(row.failure_message, "failure_message", 512);
  const status = row.evidence_id !== null && row.promotion_evidence_id === row.evidence_id
    ? "verified"
    : row.attempt_outcome === "rejected" ? "rejected" : "candidate";
  return {
    id, status, quote, quoteTruncated, prefix, suffix, observedAt, availableAt, capturedAt,
    sha256, byteLength, mediaType, sourceUri, failureCode, failureMessage,
  };
}

function candidateReviewSummary(candidate: EvidenceCandidate): Record<string, string | number> {
  const sanitizedExact = sqliteSafeText(candidate.selector.exact);
  const quote = Array.from(sanitizedExact);
  const quoteChanged = sanitizedExact !== candidate.selector.exact;
  return {
    candidate_id: candidate.id,
    quote: quote.length > 240 ? `${quote.slice(0, 239).join("")}…` : sanitizedExact,
    quote_truncated: quote.length > 240 || quoteChanged ? 1 : 0,
    prefix: sqliteSafeText(candidate.selector.prefix),
    suffix: sqliteSafeText(candidate.selector.suffix),
    observed_at: candidate.observedAt,
    available_at: candidate.snapshot.availableAt,
    captured_at: candidate.snapshot.capturedAt,
    sha256: candidate.snapshot.sha256,
    byte_length: candidate.snapshot.byteLength,
    media_type: sqliteSafeText(candidate.snapshot.mediaType),
    source_uri: sqliteSafeText(candidate.snapshot.sourceUri),
  };
}

function sqliteSafeText(value: string): string {
  return value.replaceAll("\0", "�");
}

function insertReviewSummary(database: DatabaseSync, candidate: EvidenceCandidate): void {
  const summary = candidateReviewSummary(candidate);
  database.prepare(`
    INSERT INTO candidate_review_summaries(
      candidate_id, quote, quote_truncated, prefix, suffix, observed_at, available_at, captured_at,
      sha256, byte_length, media_type, source_uri
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(candidate_id) DO NOTHING
  `).run(...Object.values(summary));
  const storedSummary = database.prepare(`
    SELECT candidate_id, quote, quote_truncated, prefix, suffix, observed_at, available_at, captured_at,
           sha256, byte_length, media_type, source_uri
    FROM candidate_review_summaries WHERE candidate_id = ?
  `).get(candidate.id);
  if (typeof storedSummary !== "object" ||
      Object.entries(summary).some(([key, value]) => (storedSummary as Record<string, unknown>)[key] !== value)) {
    invalidStoredEnvelope();
  }
}

function boundedDatabaseString(value: unknown, column: string, maxLength: number, emptyAllowed: boolean): string {
  const text = databaseString(value, column);
  if ((!emptyAllowed && text.length === 0) || Array.from(text).length > maxLength) invalidStoredEnvelope();
  return text;
}

function boundedDatabaseCharacters(value: unknown, column: string, maxLength: number): string {
  const text = databaseString(value, column);
  if (Array.from(text).length > maxLength) invalidStoredEnvelope();
  return text;
}

function nullableDatabaseString(value: unknown, column: string, maxLength: number): string | null {
  return value === null ? null : boundedDatabaseString(value, column, maxLength, false);
}

function timestampDatabaseString(value: unknown, column: string): string {
  const timestamp = boundedDatabaseString(value, column, 64, false);
  try { parseTimestamp(timestamp); } catch { invalidStoredEnvelope(); }
  return timestamp;
}

function databaseString(value: unknown, column: string): string {
  if (typeof value !== "string") throw new TypeError(`Invalid database value for ${column}`);
  return value;
}

function refuseSymbolicLink(path: string): void {
  try {
    if (lstatSync(path).isSymbolicLink()) {
      throw new Error(`Workspace database path must not be a symbolic link: ${path}`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function snapshotReference(snapshot: SourceSnapshot): string {
  return `snapshot_${canonicalJsonSha256(snapshot)}`;
}

function boundedJson(value: unknown, label: string): string {
  const json = JSON.stringify(value);
  const bytes = Buffer.byteLength(json);
  if (bytes > MAX_RECORD_BYTES) throw new RangeError(`${label} exceeds ${String(MAX_RECORD_BYTES)} bytes`);
  return json;
}

function assertIdentifier(value: string, label: string): void {
  if (!value || value.length > 256) throw new RangeError(`${label} must contain 1 to 256 characters`);
}

function assertLimit(limit: number): void {
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_QUERY_LIMIT) {
    throw new RangeError(`limit must be an integer from 1 to ${String(MAX_QUERY_LIMIT)}`);
  }
}

function assertDate(value: Date, label: string): void {
  if (Number.isNaN(value.getTime())) throw new RangeError(`${label} must be a valid date`);
}

function assertStoredJson(
  database: DatabaseSync,
  table: "source_snapshots" | "candidates" | "web_source_captures",
  column: "snapshot_ref" | "candidate_id" | "capture_id",
  id: string,
  expected: string,
): void {
  const row = database.prepare(`SELECT record_json FROM ${table} WHERE ${column} = ?`).get(id) as unknown as JsonRow | undefined;
  if (!row) throw new Error(`Missing immutable ${table} record: ${id}`);
  if (row.record_json !== expected) throw new Error(`Conflicting immutable ${table} record: ${id}`);
}

function parseRecord<T extends EvidenceCandidate | VerifiedEvidence | WebSourceCapture>(
  row: JsonRow | undefined,
  expectedKind: T["kind"],
  expectedId?: string,
): T | undefined {
  if (!row) return undefined;
  const record = parseJson(row.record_json);
  if (expectedKind === "EvidenceCandidate") assertEvidenceCandidate(record);
  else if (expectedKind === "VerifiedEvidence") assertVerifiedEvidence(record);
  else if (typeof record !== "object" || record === null || !("kind" in record) || record.kind !== expectedKind) {
    throw new Error(`Stored record kind mismatch: expected ${expectedKind}`);
  }
  if (expectedId !== undefined && (!("id" in record) || record.id !== expectedId)) invalidStoredEnvelope();
  return record as T;
}

function assertEvidenceBinding(evidence: VerifiedEvidence, candidate: EvidenceCandidate): void {
  if (evidence.candidateId !== candidate.id || evidence.observedAt !== candidate.observedAt ||
      !isDeepStrictEqual(evidence.snapshot, candidate.snapshot) ||
      !isDeepStrictEqual(evidence.selector, candidate.selector) ||
      !isDeepStrictEqual(evidence.citationView, candidate.citationView)) invalidStoredEnvelope();
}

function invalidStoredEnvelope(): never {
  throw new PromotionError("INVALID_EVIDENCE_ENVELOPE", "Stored Evidence envelope is invalid or inconsistent");
}

function parseJson(json: string): unknown {
  return JSON.parse(json) as unknown;
}

function verifyPromotionRows(rows: PromotionRow[]): void {
  let previousHash: string | null = null;
  let previousSequence = 0;
  for (const row of rows) {
    const payload = parseJson(row.record_json);
    if (!isPromotionRecordPayload(payload)) throw new Error(`Invalid promotion record payload at sequence ${String(row.sequence)}`);
    if (
      row.sequence !== previousSequence + 1 ||
      payload.candidateId !== row.candidate_id ||
      payload.evidenceId !== row.evidence_id ||
      payload.snapshotRef !== row.snapshot_ref ||
      payload.promotedAt !== row.promoted_at ||
      payload.previousRecordSha256 !== row.previous_record_sha256 ||
      row.previous_record_sha256 !== previousHash ||
      canonicalJsonSha256(payload) !== row.record_sha256
    ) {
      throw new Error(`Promotion history integrity failure at sequence ${String(row.sequence)}`);
    }
    previousHash = row.record_sha256;
    previousSequence = row.sequence;
  }
}

function isPromotionRecordPayload(value: unknown): value is PromotionRecordPayload {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.candidateId === "string" &&
    typeof record.evidenceId === "string" &&
    typeof record.snapshotRef === "string" &&
    typeof record.promotedAt === "string" &&
    (record.previousRecordSha256 === null || typeof record.previousRecordSha256 === "string")
  );
}
