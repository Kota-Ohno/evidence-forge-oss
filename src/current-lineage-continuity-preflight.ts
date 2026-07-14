import {
  loadEvidencePacketCollectionLineageBundle,
  type EvidencePacketCollectionLineageVerification,
} from "./evidence-packet-collection-lineage-bundle.js";
import {
  verifyCrossReleaseLineageAcceptanceReceipt,
  type LineageContinuityVerification,
} from "./lineage-continuity-receipt.js";
import { diagnosticError } from "./diagnostics.js";

export interface CurrentLineageContinuityPreflight {
  readonly version: 1;
  readonly kind: "EvidenceForgeCurrentLineageContinuityPreflight";
  readonly outcome: "verified";
  readonly olderVersion: string;
  readonly newerVersion: string;
  readonly currentLineageSha256: string;
  readonly currentPacketCount: number;
  readonly currentTransitionCount: number;
  readonly continuityReceiptSha256: string;
  readonly currentLineageReaudited: true;
  readonly packsReexecuted: false;
  readonly timestampAttested: false;
}

export async function preflightCurrentLineageContinuity(input: {
  readonly lineagePath: string;
  readonly expectedLineageSha256: string;
  readonly receiptPath: string;
  readonly expectedReceiptSha256: string;
}): Promise<CurrentLineageContinuityPreflight> {
  const continuity = verifyCrossReleaseLineageAcceptanceReceipt(
    input.receiptPath, input.expectedReceiptSha256,
  );
  const { verification: lineage } = await loadEvidencePacketCollectionLineageBundle(
    input.lineagePath, input.expectedLineageSha256,
  );
  assertCurrentLineageContinuityBinding(lineage, continuity);
  return {
    version: 1,
    kind: "EvidenceForgeCurrentLineageContinuityPreflight",
    outcome: "verified",
    olderVersion: continuity.olderVersion,
    newerVersion: continuity.newerVersion,
    currentLineageSha256: lineage.lineageSha256,
    currentPacketCount: lineage.packetCount,
    currentTransitionCount: lineage.transitionCount,
    continuityReceiptSha256: continuity.receiptSha256,
    currentLineageReaudited: true,
    packsReexecuted: false,
    timestampAttested: false,
  };
}

export function assertCurrentLineageContinuityBinding(
  lineage: EvidencePacketCollectionLineageVerification,
  continuity: LineageContinuityVerification,
): void {
  if (continuity.nextLineageSha256 !== lineage.lineageSha256) {
    throw diagnosticError(
      "CURRENT_LINEAGE_CONTINUITY_HEAD_MISMATCH",
      "Lineage continuity receipt does not match the current lineage head",
    );
  }
  if (continuity.nextPacketCount !== lineage.packetCount ||
      continuity.nextTransitionCount !== lineage.transitionCount) {
    throw diagnosticError(
      "CURRENT_LINEAGE_CONTINUITY_COUNT_MISMATCH",
      "Lineage continuity receipt does not match the current lineage counts",
    );
  }
}
