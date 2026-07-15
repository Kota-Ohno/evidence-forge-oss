import { createHash } from "node:crypto";
import type { EvidenceCandidate, VerifiedEvidence } from "./domain.js";
import { assertCitationView, CitationViewError } from "./html-citation-view.js";

export const SOL_LEDGER_PROTOCOL_COMMIT = "6139085503dec278e86cf0d9673d84ba34eb1e92";
export const SOL_LEDGER_SCHEMA_VERSION = "0.1.0" as const;
export const EVIDENCE_PROMOTION_POLICY = "evidence-forge/verified-local-citation@1" as const;
export const EVIDENCE_FORGE_SOFTWARE = "evidence-forge@6.4.0" as const;

export interface SolLedgerArtifactRef {
  readonly artifactId: string;
  readonly mediaType: string;
  readonly byteLength: number;
  readonly storage: "local_blob";
  readonly locator: string;
  readonly redaction: "none";
}

export interface EvidencePromotionPayload extends Record<string, unknown> {
  readonly promotionPolicy: typeof EVIDENCE_PROMOTION_POLICY;
  readonly protocolCommit: typeof SOL_LEDGER_PROTOCOL_COMMIT;
  readonly evidenceId: string;
  readonly candidateId: string;
  readonly sourceArtifactId: string;
  readonly selector: VerifiedEvidence["selector"];
  readonly citationView?: VerifiedEvidence["citationView"];
  readonly availableAt: string;
  readonly observedAt: string;
  readonly verifiedAt: string;
}

export interface SolLedgerEventEnvelope {
  readonly schemaVersion: typeof SOL_LEDGER_SCHEMA_VERSION;
  readonly eventId: string;
  readonly eventType: "evidence_forge.evidence_promoted";
  readonly occurredAt: string;
  readonly recordedAt: string;
  readonly actor: {
    readonly kind: "system";
    readonly id: "evidence-forge";
    readonly software: typeof EVIDENCE_FORGE_SOFTWARE;
  };
  readonly subjectRefs: readonly string[];
  readonly payload: EvidencePromotionPayload;
  readonly security: {
    readonly sensitivity: "private";
    readonly contentMode: "full_opt_in";
    readonly retentionClass: "user_managed";
  };
  readonly integrity: {
    readonly payloadSha256: string;
    readonly previousEventSha256: string | null;
  };
}

export interface SolLedgerProvenanceEdge {
  readonly edgeId: string;
  readonly relationship: "derived_from";
  readonly fromRef: string;
  readonly toRef: string;
  readonly recordedAt: string;
  readonly attributes: {
    readonly promotionEventRef: string;
    readonly protocolCommit: typeof SOL_LEDGER_PROTOCOL_COMMIT;
  };
}

export interface SolLedgerEvidenceBundle {
  readonly protocolCommit: typeof SOL_LEDGER_PROTOCOL_COMMIT;
  readonly artifact: SolLedgerArtifactRef;
  readonly event: SolLedgerEventEnvelope;
  readonly provenance: SolLedgerProvenanceEdge;
}

export function toSolLedgerBundle(
  evidence: VerifiedEvidence | EvidenceCandidate,
  options: { readonly previousEventSha256?: string | null } = {},
): SolLedgerEvidenceBundle {
  if (evidence.kind !== "VerifiedEvidence") {
    throw new TypeError("Sol Ledger adapter input must have kind VerifiedEvidence");
  }
  if (Object.hasOwn(evidence, "citationView") ||
      evidence.snapshot.mediaType.split(";", 1)[0]?.trim().toLowerCase() === "text/html") {
    try { assertCitationView(evidence.citationView, evidence.snapshot); }
    catch (error) {
      if (error instanceof CitationViewError) throw new TypeError("Sol Ledger adapter citation view is invalid");
      throw error;
    }
  }
  const previousEventSha256 = options.previousEventSha256 ?? null;
  if (previousEventSha256 !== null && !/^[0-9a-f]{64}$/u.test(previousEventSha256)) {
    throw new TypeError("previousEventSha256 must be 64 lowercase hexadecimal characters or null");
  }

  const artifactId = `artifact:sha256:${evidence.snapshot.sha256}`;
  const evidenceRef = `evidence:${evidence.id}`;
  const eventId = `evt_${digest(`promotion:${evidence.id}`).slice(0, 24)}`;
  const payload: EvidencePromotionPayload = {
    promotionPolicy: EVIDENCE_PROMOTION_POLICY,
    protocolCommit: SOL_LEDGER_PROTOCOL_COMMIT,
    evidenceId: evidence.id,
    candidateId: evidence.candidateId,
    sourceArtifactId: artifactId,
    selector: evidence.selector,
    ...(evidence.citationView ? { citationView: evidence.citationView } : {}),
    availableAt: evidence.snapshot.availableAt,
    observedAt: evidence.observedAt,
    verifiedAt: evidence.verifiedAt,
  };
  const artifact: SolLedgerArtifactRef = {
    artifactId,
    mediaType: evidence.snapshot.mediaType.replaceAll(/\s+/gu, ""),
    byteLength: evidence.snapshot.byteLength,
    storage: "local_blob",
    locator: `objects/sha256/${evidence.snapshot.sha256.slice(0, 2)}/${evidence.snapshot.sha256.slice(2)}`,
    redaction: "none",
  };
  const event: SolLedgerEventEnvelope = {
    schemaVersion: SOL_LEDGER_SCHEMA_VERSION,
    eventId,
    eventType: "evidence_forge.evidence_promoted",
    occurredAt: evidence.verifiedAt,
    recordedAt: evidence.verifiedAt,
    actor: {
      kind: "system",
      id: "evidence-forge",
      software: EVIDENCE_FORGE_SOFTWARE,
    },
    subjectRefs: [evidenceRef, artifactId],
    payload,
    security: {
      sensitivity: "private",
      contentMode: "full_opt_in",
      retentionClass: "user_managed",
    },
    integrity: {
      payloadSha256: canonicalJsonSha256(payload),
      previousEventSha256,
    },
  };
  const provenance: SolLedgerProvenanceEdge = {
    edgeId: `edge_${digest(`derived-from:${evidence.id}:${artifactId}`).slice(0, 24)}`,
    relationship: "derived_from",
    fromRef: evidenceRef,
    toRef: artifactId,
    recordedAt: evidence.verifiedAt,
    attributes: {
      promotionEventRef: eventId,
      protocolCommit: SOL_LEDGER_PROTOCOL_COMMIT,
    },
  };

  return { protocolCommit: SOL_LEDGER_PROTOCOL_COMMIT, artifact, event, provenance };
}

export function canonicalJsonSha256(value: unknown): string {
  return digest(canonicalJson(value));
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot encode non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => {
      const nested = object[key];
      if (nested === undefined) throw new TypeError("Canonical JSON cannot encode undefined");
      return `${JSON.stringify(key)}:${canonicalJson(nested)}`;
    }).join(",")}}`;
  }
  throw new TypeError(`Canonical JSON cannot encode ${typeof value}`);
}
