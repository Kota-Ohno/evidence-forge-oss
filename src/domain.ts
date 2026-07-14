export interface SourceSnapshot {
  readonly mediaType: string;
  readonly sha256: string;
  readonly byteLength: number;
  readonly objectPath: string;
  readonly sourceUri: string;
  readonly capturedAt: string;
  readonly availableAt: string;
}

export interface WebRedirectHop {
  readonly url: string;
  readonly status: number;
  readonly location: string;
}

export interface WebSourceCapture {
  readonly kind: "WebSourceCapture";
  readonly id: string;
  readonly snapshot: SourceSnapshot;
  readonly wireResponse: {
    readonly sha256: string;
    readonly byteLength: number;
    readonly objectPath: string;
    readonly contentEncoding: string;
  };
  readonly requestedUrl: string;
  readonly canonicalUrl: string;
  readonly redirectChain: readonly WebRedirectHop[];
  readonly status: number;
  readonly representationHeaders: Readonly<Record<string, string>>;
  readonly retrievedAt: string;
  readonly availableAt: string;
  readonly availabilityBasis: "successful-http-response-completed";
}

export interface TextQuoteSelector {
  readonly type: "TextQuoteSelector";
  readonly exact: string;
  readonly prefix: string;
  readonly suffix: string;
}

export interface CitationView {
  readonly kind: "DerivedCitationView";
  readonly transformation: "evidence-forge/html-text@1";
  readonly sourceSha256: string;
  readonly mediaType: "text/plain; charset=utf-8";
  readonly sha256: string;
  readonly byteLength: number;
}

export interface EvidenceCandidate {
  readonly kind: "EvidenceCandidate";
  readonly id: string;
  readonly snapshot: SourceSnapshot;
  readonly selector: TextQuoteSelector;
  readonly citationView?: CitationView;
  readonly observedAt: string;
}

export interface VerifiedEvidence {
  readonly kind: "VerifiedEvidence";
  readonly id: string;
  readonly candidateId: string;
  readonly snapshot: SourceSnapshot;
  readonly selector: TextQuoteSelector;
  readonly citationView?: CitationView;
  readonly observedAt: string;
  readonly verifiedAt: string;
}

export type PromotionFailureCode =
  | "INVALID_CANDIDATE_KIND"
  | "INVALID_EVIDENCE_ENVELOPE"
  | "INVALID_TIMESTAMP"
  | "SNAPSHOT_MISSING"
  | "SNAPSHOT_HASH_MISMATCH"
  | "SNAPSHOT_SIZE_MISMATCH"
  | "SNAPSHOT_TOO_LARGE"
  | "SNAPSHOT_PATH_UNSAFE"
  | "TIMESTAMP_ORDER_INVALID"
  | "VERIFICATION_TIME_INVALID"
  | "SELECTOR_NOT_FOUND"
  | "SELECTOR_AMBIGUOUS"
  | "SELECTOR_CONTEXT_MISMATCH"
  | "CITATION_VIEW_INVALID"
  | "CITATION_VIEW_HASH_MISMATCH"
  | "CITATION_VIEW_TOO_LARGE"
  | "HTML_PARSE_FAILED";

export class PromotionError extends Error {
  constructor(
    readonly code: PromotionFailureCode,
    message: string,
  ) {
    super(message);
    this.name = "PromotionError";
  }
}
