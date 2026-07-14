import { lstatSync, readFileSync } from "node:fs";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const MAX_STACK_REPORT_BYTES = 64 * 1024;
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;

export interface RepositoryState {
  readonly commit: string;
  readonly clean: boolean;
}

export interface StackAcceptanceReport {
  readonly version: 1;
  readonly recordedAt?: string;
  readonly outcome: "verified";
  readonly eventCount: 4;
  readonly trustedHeadSha256: string;
  readonly candidateKind: "EvidenceCandidate";
  readonly evidenceKind: "VerifiedEvidence";
  readonly candidateLinked: true;
  readonly integrity?: { readonly algorithm: "sha256-jcs"; readonly reportSha256: string };
  readonly revisions: {
    readonly evidenceForge: RepositoryState;
    readonly agentBlackBox: RepositoryState;
    readonly solLedger: RepositoryState;
  };
}

export function loadStackAcceptanceReport(path: string): StackAcceptanceReport {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("Stack report must be a regular file");
  if (metadata.size > MAX_STACK_REPORT_BYTES) throw new Error("Stack report exceeds 64 KiB");
  return parseStackAcceptanceReport(JSON.parse(readFileSync(path, "utf8")) as unknown);
}

export function parseStackAcceptanceReport(value: unknown): StackAcceptanceReport {
  const report = object(value, "report");
  if (report.integrity !== undefined) {
    assertKeys(report, ["version", "recordedAt", "outcome", "eventCount", "trustedHeadSha256", "candidateKind", "evidenceKind", "candidateLinked", "revisions", "integrity"], "report");
  }
  if (report.version !== 1 || report.outcome !== "verified" || report.eventCount !== 4 ||
      report.candidateKind !== "EvidenceCandidate" || report.evidenceKind !== "VerifiedEvidence" ||
      report.candidateLinked !== true || typeof report.trustedHeadSha256 !== "string" ||
      !SHA256.test(report.trustedHeadSha256)) {
    throw new Error("Stack report failed verification schema");
  }
  const revisions = object(report.revisions, "revisions");
  if (report.integrity !== undefined) assertKeys(revisions, ["evidenceForge", "agentBlackBox", "solLedger"], "revisions");
  if (report.recordedAt !== undefined && (typeof report.recordedAt !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(report.recordedAt) ||
      Number.isNaN(Date.parse(report.recordedAt)))) {
    throw new Error("Stack report recordedAt failed verification schema");
  }
  const normalized: StackAcceptanceReport = {
    version: 1, outcome: "verified", eventCount: 4, trustedHeadSha256: report.trustedHeadSha256,
    ...(typeof report.recordedAt === "string" ? { recordedAt: report.recordedAt } : {}),
    candidateKind: "EvidenceCandidate", evidenceKind: "VerifiedEvidence", candidateLinked: true,
    revisions: {
      evidenceForge: repository(revisions.evidenceForge, "Evidence Forge"),
      agentBlackBox: repository(revisions.agentBlackBox, "Agent Black Box"),
      solLedger: repository(revisions.solLedger, "Sol Ledger"),
    },
  };
  if (report.integrity === undefined) return normalized;
  const integrity = object(report.integrity, "integrity");
  assertKeys(integrity, ["algorithm", "reportSha256"], "integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.reportSha256 !== "string" ||
      !SHA256.test(integrity.reportSha256) || canonicalJsonSha256(normalized) !== integrity.reportSha256) {
    throw new Error("Stack report integrity verification failed");
  }
  return { ...normalized, integrity: { algorithm: "sha256-jcs", reportSha256: integrity.reportSha256 } };
}

function repository(value: unknown, label: string): RepositoryState {
  const state = object(value, label);
  if (typeof state.commit !== "string" || !COMMIT.test(state.commit) || typeof state.clean !== "boolean") {
    throw new Error(`${label} revision failed verification schema`);
  }
  return { commit: state.commit, clean: state.clean };
}

function assertKeys(value: Record<string, unknown>, allowed: string[], label: string): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(`${label} contains an unknown field`);
  if (label !== "report" && label !== "revisions" && label !== "integrity") return;
  if (label === "revisions") {
    for (const name of ["evidenceForge", "agentBlackBox", "solLedger"]) {
      assertKeys(object(value[name], name), ["commit", "clean"], name);
    }
  }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}
