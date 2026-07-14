import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { isDeepStrictEqual } from "node:util";
import { LocalWorkspace, type ReviewItem } from "./workspace.js";
import { assertWebSourceCapture } from "./web-capture.js";
import { citationText } from "./html-citation-view.js";
import { loadStackAcceptanceReport, type StackAcceptanceReport } from "./stack-report.js";
import { verifyStackReportSignatures, type VerifiedStackReportSignatures } from "./stack-signature.js";
import { loadStackReviewBundle, verifyStackReviewBundle } from "./stack-review-bundle.js";
import { loadTrustRotationHistory, verifyTrustRotationHistory, type VerifiedTrustRotationHistory } from "./trust-rotation.js";
import { loadTrustManifest } from "./trust-manifest.js";
import { loadReleaseEvidenceIndex } from "./release-evidence-index.js";
import { loadReleaseArchiveAuditReceipt } from "./release-archive-audit.js";
import { loadUpgradeHistoryIndex } from "./upgrade-history-index.js";
import { loadUpgradeHistoryAuditReceipt } from "./upgrade-history-audit.js";
import { loadWorkspaceAcceptanceReceipt, verifyWorkspaceAcceptanceReceipt } from "./workspace-acceptance-receipt.js";
import { verifyCrossReleaseLineageAcceptanceReceipt } from "./lineage-continuity-receipt.js";
import { assertCurrentLineageContinuityBinding } from "./current-lineage-continuity-preflight.js";
import { REVIEW_HTML, REVIEW_JAVASCRIPT, REVIEW_STYLES } from "./review-assets.js";
import { loadEvidencePacket, type PortableEvidencePacket } from "./evidence-packet.js";
import {
  auditEvidencePacketCollection,
  loadEvidencePacketCollectionAuditReceipt,
} from "./evidence-packet-collection.js";
import { loadEvidencePacketCollectionBundle, type EvidencePacketCollectionBundle } from "./evidence-packet-collection-bundle.js";
import { loadEvidencePacketCollectionLineageBundle } from "./evidence-packet-collection-lineage-bundle.js";
import { loadEvidencePacketTransitionHistoryIndex } from "./evidence-packet-transition-history.js";
import { loadEvidencePacketTransitionHistoryAuditReceipt } from "./evidence-packet-transition-history-audit.js";

const MAX_CONTEXT_BYTES = 16 * 1024 * 1024;
const MAX_REVIEW_ITEMS = 500;

export interface ReviewServer {
  readonly url: string;
  close(): Promise<void>;
}

interface ReviewWorkspaceAcceptance {
  readonly version: 1;
  readonly kind: "EvidenceForgeReviewWorkspaceAcceptance";
  readonly outcome: "verified";
  readonly packageVersion: string;
  readonly releaseCount: number;
  readonly transitionCount: number;
  readonly firstRelease: string;
  readonly latestRelease: string;
  readonly receiptSha256: string;
  readonly timestampAttested: false;
}

interface ReviewLineageContinuity {
  readonly version: 1;
  readonly kind: "EvidenceForgeReviewLineageContinuity";
  readonly outcome: "verified";
  readonly olderVersion: string;
  readonly newerVersion: string;
  readonly previousLineageSha256: string;
  readonly nextLineageSha256: string;
  readonly previousPacketCount: number;
  readonly nextPacketCount: number;
  readonly previousTransitionCount: number;
  readonly nextTransitionCount: number;
  readonly receiptSha256: string;
  readonly packsReexecuted: false;
  readonly lineagesReaudited: false;
  readonly timestampAttested: false;
}

export async function startReviewServer(input: {
  databasePath?: string;
  evidencePacketPath?: string;
  evidencePacketSha256?: string;
  evidencePacketPaths?: string[];
  evidencePacketIndexPath?: string;
  evidencePacketIndexSha256?: string;
  evidencePacketAuditReceiptPath?: string;
  evidencePacketAuditReceiptSha256?: string;
  evidencePacketBundlePath?: string;
  evidencePacketBundleSha256?: string;
  evidencePacketLineagePath?: string;
  evidencePacketLineageSha256?: string;
  port?: number;
  stackReportPath?: string;
  stackReportPaths?: string[];
  stackBundlePath?: string;
  stackSignaturePath?: string;
  stackSignaturePaths?: string[];
  trustedPublicKeyPaths?: string[];
  trustedKeyIds?: string[];
  trustHistoryPath?: string;
  trustAnchorKeyIds?: readonly string[];
  trustAnchorThreshold?: number;
  trustHistorySha256?: string;
  trustManifestPath?: string;
  trustManifestSha256?: string;
  signatureThreshold?: number;
  trustValidFrom?: string;
  trustValidUntil?: string;
  revokedKeyIds?: string[];
  releaseIndexPath?: string;
  releaseIndexSha256?: string;
  archiveAuditReceiptPath?: string;
  archiveAuditReceiptSha256?: string;
  upgradeHistoryIndexPath?: string;
  upgradeHistoryIndexSha256?: string;
  upgradeHistoryAuditReceiptPath?: string;
  upgradeHistoryAuditReceiptSha256?: string;
  workspaceAcceptanceReceiptPath?: string;
  workspaceAcceptanceReceiptSha256?: string;
  lineageContinuityReceiptPath?: string;
  lineageContinuityReceiptSha256?: string;
  packetTransitionHistoryIndexPath?: string;
  packetTransitionHistoryIndexSha256?: string;
  packetTransitionHistoryAuditReceiptPath?: string;
  packetTransitionHistoryAuditReceiptSha256?: string;
}): Promise<ReviewServer> {
  if (input.port !== undefined && (!Number.isInteger(input.port) || input.port < 0 || input.port > 65_535)) {
    throw new RangeError("Review server port must be an integer from 0 to 65535");
  }
  const packetConfigured = [input.evidencePacketPath, input.evidencePacketSha256].filter(Boolean).length;
  if (packetConfigured !== 0 && packetConfigured !== 2) {
    throw new Error("Evidence packet review requires a packet and expected SHA-256");
  }
  const collectionAnchors = [input.evidencePacketIndexPath, input.evidencePacketIndexSha256,
    input.evidencePacketAuditReceiptPath, input.evidencePacketAuditReceiptSha256].filter(Boolean).length;
  const collectionPathsConfigured = Boolean(input.evidencePacketPaths?.length);
  if ((collectionAnchors !== 0 || collectionPathsConfigured) && (collectionAnchors !== 4 || !collectionPathsConfigured)) {
    throw new Error("Evidence packet collection review requires an index, expected index SHA-256, audit receipt, expected audit SHA-256, and packet files");
  }
  if (packetConfigured && collectionAnchors) throw new Error("Single Evidence packet review cannot be mixed with a packet collection");
  const bundleConfigured = [input.evidencePacketBundlePath, input.evidencePacketBundleSha256].filter(Boolean).length;
  if (bundleConfigured !== 0 && bundleConfigured !== 2) {
    throw new Error("Evidence packet collection bundle review requires a bundle and expected SHA-256");
  }
  if (bundleConfigured && (packetConfigured || collectionAnchors || collectionPathsConfigured)) {
    throw new Error("Evidence packet collection bundle cannot be mixed with loose packet review inputs");
  }
  const lineageConfigured = [input.evidencePacketLineagePath, input.evidencePacketLineageSha256].filter(Boolean).length;
  if (lineageConfigured !== 0 && lineageConfigured !== 2) {
    throw new Error("Evidence packet collection lineage review requires a lineage bundle and expected SHA-256");
  }
  if (lineageConfigured && (packetConfigured || collectionAnchors || collectionPathsConfigured || bundleConfigured)) {
    throw new Error("Evidence packet collection lineage cannot be mixed with other packet review inputs");
  }
  if (input.databasePath && (packetConfigured || collectionAnchors || bundleConfigured || lineageConfigured)) {
    throw new Error("Evidence packet review cannot be mixed with a workspace database");
  }
  const loadedLineage = lineageConfigured === 2 ? await loadEvidencePacketCollectionLineageBundle(
    input.evidencePacketLineagePath as string, input.evidencePacketLineageSha256 as string,
  ) : undefined;
  let packetReviews: readonly PacketReviewState[] | undefined;
  let collectionBundle: EvidencePacketCollectionBundle | undefined;
  if (packetConfigured === 2) {
    packetReviews = [await loadPacketReview(input.evidencePacketPath as string, input.evidencePacketSha256 as string)];
  } else if (collectionAnchors === 4) {
    const audited = await auditEvidencePacketCollection({
      indexPath: input.evidencePacketIndexPath as string,
      expectedIndexSha256: input.evidencePacketIndexSha256 as string,
      packetPaths: input.evidencePacketPaths as string[],
    });
    const retainedReceipt = loadEvidencePacketCollectionAuditReceipt(
      input.evidencePacketAuditReceiptPath as string, input.evidencePacketAuditReceiptSha256,
    );
    if (!isDeepStrictEqual(audited.receipt, retainedReceipt)) {
      throw new Error("Packet collection audit receipt does not match the verified collection");
    }
    packetReviews = audited.packets.map(createPacketReview);
  } else if (bundleConfigured === 2) {
    const loaded = await loadEvidencePacketCollectionBundle(
      input.evidencePacketBundlePath as string, input.evidencePacketBundleSha256 as string,
    );
    collectionBundle = loaded.bundle;
    packetReviews = loaded.bundle.packets.map((record) => createPacketReview(record.packet));
  } else if (loadedLineage) {
    collectionBundle = loadedLineage.lineage.collectionBundle;
    packetReviews = collectionBundle.packets.map((record) => createPacketReview(record.packet));
  }
  const archiveConfigured = [input.releaseIndexPath, input.releaseIndexSha256, input.archiveAuditReceiptPath, input.archiveAuditReceiptSha256].filter(Boolean).length;
  if (archiveConfigured !== 0 && archiveConfigured !== 4) throw new Error("Archive inventory requires an index, expected index SHA-256, audit receipt, and expected audit SHA-256");
  const archiveState = archiveConfigured === 4 ? loadArchiveInventory(
    input.releaseIndexPath as string, input.releaseIndexSha256 as string, input.archiveAuditReceiptPath as string, input.archiveAuditReceiptSha256 as string,
  ) : undefined;
  const upgradeConfigured = [input.upgradeHistoryIndexPath, input.upgradeHistoryIndexSha256,
    input.upgradeHistoryAuditReceiptPath, input.upgradeHistoryAuditReceiptSha256].filter(Boolean).length;
  if (upgradeConfigured !== 0 && upgradeConfigured !== 4) {
    throw new Error("Upgrade inventory requires an index, expected index SHA-256, audit receipt, and expected audit SHA-256");
  }
  const upgradeState = upgradeConfigured === 4 ? loadUpgradeInventory(
    input.upgradeHistoryIndexPath as string, input.upgradeHistoryIndexSha256 as string,
    input.upgradeHistoryAuditReceiptPath as string, input.upgradeHistoryAuditReceiptSha256 as string,
  ) : undefined;
  const archiveInventory = archiveState?.api, upgradeInventory = upgradeState?.api;
  const coverageReadiness = archiveState && upgradeState ? verifyCoverageReadiness(archiveState, upgradeState) : undefined;
  const acceptanceConfigured = [input.workspaceAcceptanceReceiptPath, input.workspaceAcceptanceReceiptSha256].filter(Boolean).length;
  if (acceptanceConfigured !== 0 && acceptanceConfigured !== 2) {
    throw new Error("Workspace acceptance review requires a receipt and expected receipt SHA-256");
  }
  const workspaceAcceptanceVerification = acceptanceConfigured === 2 ? verifyWorkspaceAcceptanceReceipt(
    input.workspaceAcceptanceReceiptPath as string, input.workspaceAcceptanceReceiptSha256 as string,
  ) : undefined;
  const workspaceAcceptance: ReviewWorkspaceAcceptance | undefined = workspaceAcceptanceVerification ? {
    ...workspaceAcceptanceVerification, kind: "EvidenceForgeReviewWorkspaceAcceptance",
  } : undefined;
  if (workspaceAcceptance && coverageReadiness) {
    const receipt = loadWorkspaceAcceptanceReceipt(
      input.workspaceAcceptanceReceiptPath as string, input.workspaceAcceptanceReceiptSha256 as string,
    );
    if (receipt.archives.releaseIndexSha256 !== input.releaseIndexSha256 ||
        receipt.archives.archiveAuditReceiptSha256 !== input.archiveAuditReceiptSha256 ||
        receipt.archives.upgradeHistoryIndexSha256 !== input.upgradeHistoryIndexSha256 ||
        receipt.archives.upgradeHistoryAuditReceiptSha256 !== input.upgradeHistoryAuditReceiptSha256 ||
        receipt.coverage.releaseCount !== coverageReadiness.releaseCount ||
        receipt.coverage.transitionCount !== coverageReadiness.transitionCount ||
        receipt.coverage.firstRelease !== coverageReadiness.firstRelease ||
        receipt.coverage.latestRelease !== coverageReadiness.latestRelease) {
      throw new Error("Workspace acceptance receipt does not match the configured coverage");
    }
  }
  const continuityConfigured = [input.lineageContinuityReceiptPath, input.lineageContinuityReceiptSha256].filter(Boolean).length;
  if (continuityConfigured !== 0 && continuityConfigured !== 2) {
    throw new Error("Lineage continuity review requires a receipt and expected receipt SHA-256");
  }
  const continuityVerification = continuityConfigured === 2 ? verifyCrossReleaseLineageAcceptanceReceipt(
    input.lineageContinuityReceiptPath as string, input.lineageContinuityReceiptSha256 as string,
  ) : undefined;
  const lineageContinuity: ReviewLineageContinuity | undefined = continuityVerification ? {
    version: 1,
    kind: "EvidenceForgeReviewLineageContinuity",
    outcome: "verified",
    olderVersion: continuityVerification.olderVersion,
    newerVersion: continuityVerification.newerVersion,
    previousLineageSha256: continuityVerification.previousLineageSha256,
    nextLineageSha256: continuityVerification.nextLineageSha256,
    previousPacketCount: continuityVerification.previousPacketCount,
    nextPacketCount: continuityVerification.nextPacketCount,
    previousTransitionCount: continuityVerification.previousTransitionCount,
    nextTransitionCount: continuityVerification.nextTransitionCount,
    receiptSha256: continuityVerification.receiptSha256,
    packsReexecuted: false,
    lineagesReaudited: false,
    timestampAttested: false,
  } : undefined;
  if (loadedLineage && continuityVerification) {
    assertCurrentLineageContinuityBinding(loadedLineage.verification, continuityVerification);
  }
  const transitionHistoryConfigured = [input.packetTransitionHistoryIndexPath, input.packetTransitionHistoryIndexSha256,
    input.packetTransitionHistoryAuditReceiptPath, input.packetTransitionHistoryAuditReceiptSha256].filter(Boolean).length;
  if (transitionHistoryConfigured !== 0 && transitionHistoryConfigured !== 4) {
    throw new Error("Packet transition history review requires an index, expected index SHA-256, audit receipt, and expected audit SHA-256");
  }
  if (loadedLineage && transitionHistoryConfigured) {
    throw new Error("Evidence packet collection lineage cannot be mixed with loose transition history inputs");
  }
  const transitionHistory = loadedLineage ? createTransitionHistoryReview(
    loadedLineage.lineage.historyIndex, loadedLineage.lineage.historyAuditReceipt,
  ) : transitionHistoryConfigured === 4 ? loadTransitionHistoryReview(
    input.packetTransitionHistoryIndexPath as string, input.packetTransitionHistoryIndexSha256 as string,
    input.packetTransitionHistoryAuditReceiptPath as string, input.packetTransitionHistoryAuditReceiptSha256 as string,
  ) : undefined;
  const bundleHistoryReadiness = collectionBundle && transitionHistory
    ? verifyBundleHistoryReadiness(collectionBundle, transitionHistory)
    : undefined;
  if (lineageContinuity && bundleHistoryReadiness && !loadedLineage) {
    throw new Error("Lineage continuity receipt can only be combined with a portable collection lineage");
  }
  const paths = input.stackReportPaths ?? (input.stackReportPath ? [input.stackReportPath] : []);
  const signaturePaths = input.stackSignaturePaths ?? (input.stackSignaturePath ? [input.stackSignaturePath] : []);
  const bundleMixedWithLooseFiles = Boolean(input.stackBundlePath &&
    (paths.length || signaturePaths.length || input.trustedPublicKeyPaths?.length));
  if (bundleMixedWithLooseFiles) throw new Error("Stack review bundle cannot be mixed with loose report, signature, or public-key files");
  if (input.trustedKeyIds?.length && !input.stackBundlePath) throw new Error("Trusted key IDs require a stack review bundle");
  const bundle = input.stackBundlePath ? loadStackReviewBundle(input.stackBundlePath) : undefined;
  const manifestConfigured = Boolean(input.trustManifestPath || input.trustManifestSha256);
  if (manifestConfigured && (!input.trustManifestPath || !input.trustManifestSha256)) {
    throw new Error("Trust manifest verification requires a manifest and expected SHA-256");
  }
  if (manifestConfigured && (input.trustedKeyIds?.length || input.signatureThreshold !== undefined ||
      input.revokedKeyIds?.length || input.trustValidFrom || input.trustValidUntil ||
      input.trustAnchorKeyIds?.length || input.trustAnchorThreshold !== undefined || input.trustHistorySha256)) {
    throw new Error("Trust manifest cannot be mixed with raw trust policy options");
  }
  const manifest = input.trustManifestPath && input.trustManifestSha256
    ? loadTrustManifest(input.trustManifestPath, input.trustManifestSha256) : undefined;
  if (manifest?.mode === "manual" && input.trustHistoryPath) throw new Error("Manual trust manifest cannot be mixed with trust rotation history");
  if (manifest?.mode === "rotation-anchor" && !input.trustHistoryPath) throw new Error("Rotation trust manifest requires trust rotation history");
  const trustedKeyIds = manifest?.mode === "manual" ? manifest.policy.trustedKeyIds : input.trustedKeyIds;
  const signatureThreshold = manifest?.mode === "manual" ? manifest.policy.threshold : input.signatureThreshold;
  const revokedKeyIds = manifest?.mode === "manual" ? manifest.policy.revokedKeyIds : input.revokedKeyIds;
  const trustValidFrom = manifest?.mode === "manual" ? manifest.policy.validFrom : input.trustValidFrom;
  const trustValidUntil = manifest?.mode === "manual" ? manifest.policy.validUntil : input.trustValidUntil;
  const trustAnchorKeyIds = manifest?.mode === "rotation-anchor" ? manifest.anchor.keyIds : input.trustAnchorKeyIds;
  const trustAnchorThreshold = manifest?.mode === "rotation-anchor" ? manifest.anchor.threshold : input.trustAnchorThreshold;
  const trustHistorySha256 = manifest?.mode === "rotation-anchor" ? manifest.anchor.historySha256 : input.trustHistorySha256;
  const rotationConfigured = Boolean(input.trustHistoryPath || trustAnchorKeyIds?.length ||
    trustAnchorThreshold !== undefined || trustHistorySha256);
  if (rotationConfigured && (!bundle || !input.trustHistoryPath || !trustAnchorKeyIds?.length ||
      trustAnchorThreshold === undefined || !trustHistorySha256)) {
    throw new Error("Trust rotation history requires a stack bundle, external anchor policy, and expected history SHA-256");
  }
  if (input.trustHistoryPath && (trustedKeyIds?.length || signatureThreshold !== undefined)) {
    throw new Error("Trust rotation history determines active trusted key IDs and signature threshold");
  }
  const verifiedRotation = input.trustHistoryPath
    ? verifyTrustRotationHistory(
      loadTrustRotationHistory(input.trustHistoryPath),
      trustAnchorKeyIds ?? [],
      trustAnchorThreshold ?? 0,
      trustHistorySha256 ?? "",
    )
    : undefined;
  if (paths.length > 20) throw new RangeError("At most 20 stack reports can be reviewed");
  const stackReports = (bundle ? [bundle.report] : paths.map(loadStackAcceptanceReport)).sort((left, right) =>
    (right.recordedAt ?? "").localeCompare(left.recordedAt ?? ""));
  if (new Set(stackReports.map((report) => report.trustedHeadSha256)).size !== stackReports.length) {
    throw new Error("Stack report history contains a duplicate trusted head");
  }
  const signatureConfigured = Boolean(signaturePaths.length || input.trustedPublicKeyPaths?.length || revokedKeyIds?.length ||
    signatureThreshold !== undefined || trustValidFrom || trustValidUntil);
  if (!bundle && signatureConfigured && (!signaturePaths.length || !stackReports[0] || !input.trustedPublicKeyPaths?.length)) {
    throw new Error("Signature verification requires a report, signatures, and trusted public keys");
  }
  if (bundle && !trustedKeyIds?.length && !verifiedRotation) throw new Error("Stack review bundle requires explicitly trusted key IDs");
  const policy = {
      ...(verifiedRotation ? { threshold: verifiedRotation.activePolicy.threshold } :
        signatureThreshold !== undefined ? { threshold: signatureThreshold } : {}),
      ...(revokedKeyIds ? { revokedKeyIds } : {}),
      ...(trustValidFrom ? { validFrom: trustValidFrom } : {}),
      ...(trustValidUntil ? { validUntil: trustValidUntil } : {}),
  };
  const verifiedSignatures = bundle
    ? (() => {
      try {
        return verifyStackReviewBundle(bundle, verifiedRotation?.activePolicy.keyIds ?? trustedKeyIds ?? [], policy);
      } catch (error) {
        if (verifiedRotation) throw new Error("Stack bundle signer set does not satisfy the active trust-rotation policy", { cause: error });
        throw error;
      }
    })()
    : signaturePaths.length && stackReports[0]
      ? verifyStackReportSignatures(stackReports[0], signaturePaths, input.trustedPublicKeyPaths ?? [], policy)
      : undefined;
  const reviewReports = stackReports.map((report, index) => index === 0 && verifiedSignatures
    ? {
      ...report,
      signature: verifiedSignatures,
      ...(verifiedRotation ? { trustRotation: rotationSummary(verifiedRotation) } : {}),
    } : report);
  const workspace = input.databasePath ? new LocalWorkspace(input.databasePath) : undefined;
  const server = createServer((request, response) => {
    void route(request, response, workspace, packetReviews, reviewReports, archiveInventory, upgradeInventory, coverageReadiness, workspaceAcceptance, lineageContinuity, transitionHistory, bundleHistoryReadiness).catch(() => {
      sendJson(response, 500, { error: "Review workspace failed safely" });
    });
  });
  server.on("close", () => { workspace?.close(); });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(input.port ?? 0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${String(port)}`,
    close: async () => { await closeServer(server); },
  };
}

type ReviewStackReport = StackAcceptanceReport & {
  signature?: VerifiedStackReportSignatures;
  trustRotation?: ReturnType<typeof rotationSummary>;
};

interface ArchiveInventory {
  readonly verifiedPackCount: number;
  readonly firstRelease: string;
  readonly latestRelease: string;
  readonly provenanceVerifiedCount: number;
  readonly reviewVerifiedCount: number;
  readonly manualTrustCount: number;
  readonly rotationTrustCount: number;
  readonly timestampAttested: false;
}

interface ArchiveInventoryState {
  readonly api: ArchiveInventory;
  readonly releases: readonly { readonly version: string; readonly packSha256: string }[];
}

interface UpgradeInventory {
  readonly version: 1;
  readonly kind: "EvidenceForgeReviewUpgradeInventory";
  readonly outcome: "verified";
  readonly verifiedTransitionCount: number;
  readonly firstRelease: string;
  readonly latestRelease: string;
  readonly timestampAttested: false;
}

interface UpgradeInventoryState {
  readonly api: UpgradeInventory;
  readonly transitions: readonly {
    readonly previousVersion: string; readonly currentVersion: string;
    readonly previousPackSha256: string; readonly currentPackSha256: string;
  }[];
}

interface CoverageReadiness {
  readonly version: 1;
  readonly kind: "EvidenceForgeReviewCoverageReadiness";
  readonly outcome: "verified";
  readonly releaseCount: number;
  readonly transitionCount: number;
  readonly firstRelease: string;
  readonly latestRelease: string;
  readonly releaseHeadsMatched: true;
  readonly timestampAttested: false;
}

interface TransitionHistoryReview {
  readonly version: 1;
  readonly kind: "EvidenceForgeReviewPacketTransitionHistory";
  readonly outcome: "verified";
  readonly transitionCount: number;
  readonly initialPacketCount: number;
  readonly latestPacketCount: number;
  readonly initialBundleSha256: string;
  readonly latestBundleSha256: string;
  readonly collectionReaudited: false;
  readonly timestampAttested: false;
}

interface BundleHistoryReadiness {
  readonly version: 1;
  readonly kind: "EvidenceForgeReviewBundleHistoryReadiness";
  readonly outcome: "verified";
  readonly packetCount: number;
  readonly transitionCount: number;
  readonly latestBundleSha256: string;
  readonly historyCollectionReaudited: false;
  readonly timestampAttested: false;
}

function verifyBundleHistoryReadiness(
  bundle: EvidencePacketCollectionBundle,
  history: TransitionHistoryReview,
): BundleHistoryReadiness {
  if (bundle.integrity.bundleSha256 !== history.latestBundleSha256 ||
      bundle.packets.length !== history.latestPacketCount) {
    throw new Error("Packet collection bundle does not match the latest transition history endpoint");
  }
  return {
    version: 1,
    kind: "EvidenceForgeReviewBundleHistoryReadiness",
    outcome: "verified",
    packetCount: bundle.packets.length,
    transitionCount: history.transitionCount,
    latestBundleSha256: bundle.integrity.bundleSha256,
    historyCollectionReaudited: false,
    timestampAttested: false,
  };
}

function loadTransitionHistoryReview(
  indexPath: string,
  expectedIndexSha256: string,
  receiptPath: string,
  expectedAuditSha256: string,
): TransitionHistoryReview {
  const index = loadEvidencePacketTransitionHistoryIndex(indexPath, expectedIndexSha256);
  const receipt = loadEvidencePacketTransitionHistoryAuditReceipt(receiptPath, expectedAuditSha256);
  return createTransitionHistoryReview(index, receipt);
}

function createTransitionHistoryReview(
  index: ReturnType<typeof loadEvidencePacketTransitionHistoryIndex>,
  receipt: ReturnType<typeof loadEvidencePacketTransitionHistoryAuditReceipt>,
): TransitionHistoryReview {
  const first = index.entries[0], latest = index.entries.at(-1);
  if (!first || !latest || receipt.history.indexSha256 !== index.integrity.indexSha256 ||
      receipt.history.transitionCount !== index.entries.length ||
      receipt.coverage.initialBundleSha256 !== first.previousBundleSha256 ||
      receipt.coverage.latestBundleSha256 !== latest.nextBundleSha256 ||
      receipt.coverage.initialPacketCount !== first.previousPacketCount ||
      receipt.coverage.latestPacketCount !== latest.nextPacketCount ||
      receipt.coverage.firstTransitionAuditSha256 !== first.transitionAuditSha256 ||
      receipt.coverage.lastTransitionAuditSha256 !== latest.transitionAuditSha256) {
    throw new Error("Packet transition history audit receipt does not match the pinned history index");
  }
  return {
    version: 1,
    kind: "EvidenceForgeReviewPacketTransitionHistory",
    outcome: "verified",
    transitionCount: index.entries.length,
    initialPacketCount: first.previousPacketCount,
    latestPacketCount: latest.nextPacketCount,
    initialBundleSha256: first.previousBundleSha256,
    latestBundleSha256: latest.nextBundleSha256,
    collectionReaudited: false,
    timestampAttested: false,
  };
}

interface PacketReviewState {
  readonly summary: ReturnType<typeof packetSummary>;
  readonly detail: ReturnType<typeof packetDetail>;
}

function loadArchiveInventory(indexPath: string, expectedIndexSha256: string, receiptPath: string, expectedAuditSha256: string): ArchiveInventoryState {
  const index = loadReleaseEvidenceIndex(indexPath, expectedIndexSha256);
  const receipt = loadReleaseArchiveAuditReceipt(receiptPath);
  const first = index.entries[0], latest = index.entries.at(-1);
  if (!/^[0-9a-f]{64}$/u.test(expectedAuditSha256) || receipt.integrity.auditSha256 !== expectedAuditSha256 ||
      !first || !latest || receipt.index.indexSha256 !== index.integrity.indexSha256 ||
      receipt.index.entryCount !== index.entries.length || receipt.archive.verifiedPackCount !== index.entries.length ||
      receipt.archive.firstRelease !== first.releaseVersion || receipt.archive.latestRelease !== latest.releaseVersion) {
    throw new Error("Archive audit receipt does not match the pinned release index");
  }
  return {
    api: {
      verifiedPackCount: receipt.archive.verifiedPackCount,
      firstRelease: receipt.archive.firstRelease,
      latestRelease: receipt.archive.latestRelease,
      provenanceVerifiedCount: receipt.signatures.provenanceVerifiedCount,
      reviewVerifiedCount: receipt.signatures.reviewVerifiedCount,
      manualTrustCount: receipt.trust.manualCount,
      rotationTrustCount: receipt.trust.rotationHistoryCount,
      timestampAttested: false,
    },
    releases: index.entries.map((entry) => ({ version: entry.releaseVersion, packSha256: entry.packSha256 })),
  };
}

function loadUpgradeInventory(indexPath: string, expectedIndexSha256: string, receiptPath: string, expectedAuditSha256: string): UpgradeInventoryState {
  const index = loadUpgradeHistoryIndex(indexPath, expectedIndexSha256);
  const receipt = loadUpgradeHistoryAuditReceipt(receiptPath);
  const first = index.entries[0], latest = index.entries.at(-1);
  if (!/^[0-9a-f]{64}$/u.test(expectedAuditSha256) || receipt.integrity.auditSha256 !== expectedAuditSha256 ||
      !first || !latest || receipt.index.indexSha256 !== index.integrity.indexSha256 ||
      receipt.index.entryCount !== index.entries.length || receipt.collection.verifiedBindingCount !== index.entries.length ||
      receipt.collection.firstRelease !== first.previousPackageVersion ||
      receipt.collection.latestRelease !== latest.currentPackageVersion) {
    throw new Error("Upgrade audit receipt does not match the pinned upgrade index");
  }
  return {
    api: {
      version: 1,
      kind: "EvidenceForgeReviewUpgradeInventory",
      outcome: "verified",
      verifiedTransitionCount: receipt.collection.verifiedBindingCount,
      firstRelease: receipt.collection.firstRelease,
      latestRelease: receipt.collection.latestRelease,
      timestampAttested: false,
    },
    transitions: index.entries.map((entry) => ({
      previousVersion: entry.previousPackageVersion, currentVersion: entry.currentPackageVersion,
      previousPackSha256: entry.previousPackSha256, currentPackSha256: entry.currentPackSha256,
    })),
  };
}

function verifyCoverageReadiness(archive: ArchiveInventoryState, upgrade: UpgradeInventoryState): CoverageReadiness {
  if (archive.releases.length !== upgrade.transitions.length + 1) {
    throw new Error("Archive and upgrade coverage do not match exactly");
  }
  for (let index = 0; index < upgrade.transitions.length; index += 1) {
    const previous = archive.releases[index], current = archive.releases[index + 1], transition = upgrade.transitions[index];
    if (!previous || !current || !transition || transition.previousVersion !== previous.version ||
        transition.currentVersion !== current.version || transition.previousPackSha256 !== previous.packSha256 ||
        transition.currentPackSha256 !== current.packSha256) {
      throw new Error("Archive and upgrade coverage do not match exactly");
    }
  }
  const first = archive.releases[0], latest = archive.releases.at(-1);
  if (!first || !latest) throw new Error("Archive and upgrade coverage do not match exactly");
  return {
    version: 1, kind: "EvidenceForgeReviewCoverageReadiness", outcome: "verified",
    releaseCount: archive.releases.length, transitionCount: upgrade.transitions.length,
    firstRelease: first.version, latestRelease: latest.version,
    releaseHeadsMatched: true, timestampAttested: false,
  };
}

function rotationSummary(rotation: VerifiedTrustRotationHistory) {
  return {
    activeSequence: rotation.activeSequence,
    verifiedEntryCount: rotation.verifiedEntryCount,
    completedRotations: rotation.completedRotations,
    scheduledCount: rotation.scheduledCount,
    latestEffectiveAt: rotation.latestEffectiveAt,
    latestAddedKeyCount: rotation.latestAddedKeyCount,
    latestRemovedKeyCount: rotation.latestRemovedKeyCount,
  };
}

async function loadPacketReview(path: string, expectedSha256: string): Promise<PacketReviewState> {
  const packet = await loadEvidencePacket(path, expectedSha256);
  return createPacketReview(packet);
}

function createPacketReview(packet: PortableEvidencePacket): PacketReviewState {
  const bytes = Buffer.from(packet.source.base64, "base64");
  const text = citationText(bytes, packet.candidate.snapshot, packet.candidate.citationView);
  const index = text.indexOf(packet.candidate.selector.exact);
  if (index < 0) throw new Error("Evidence packet citation is unavailable after verification");
  const context = {
    integrity: "verified" as const,
    before: text.slice(Math.max(0, index - 280), index),
    exact: packet.candidate.selector.exact,
    after: text.slice(index + packet.candidate.selector.exact.length,
      index + packet.candidate.selector.exact.length + 280),
  };
  return { summary: packetSummary(packet), detail: packetDetail(packet, context) };
}

function packetSummary(packet: PortableEvidencePacket) {
  return {
    id: packet.candidate.id, status: "verified" as const,
    quote: packet.candidate.selector.exact, prefix: packet.candidate.selector.prefix,
    suffix: packet.candidate.selector.suffix, observedAt: packet.candidate.observedAt,
    availableAt: packet.candidate.snapshot.availableAt, capturedAt: packet.candidate.snapshot.capturedAt,
    sha256: packet.source.sha256, byteLength: packet.source.byteLength,
    mediaType: boundedDisplay(packet.source.mediaType, 256),
    source: "持ち運び用の検証済み記録", failureCode: null, failureMessage: null,
  };
}

function packetDetail(packet: PortableEvidencePacket, context: {
  readonly integrity: "verified"; readonly before: string; readonly exact: string; readonly after: string;
}) {
  return {
    ...packetSummary(packet),
    attempts: [{
      attemptedAt: packet.evidence.verifiedAt, outcome: "verified" as const,
      failureCode: null, failureMessage: null,
    }],
    context,
    provenance: {
      kind: "packet" as const, integrity: "verified" as const,
      assurance: "externally-pinned-packet-head" as const,
      packetSha256: packet.integrity.packetSha256, timestampAttested: false as const,
    },
    citationView: packet.candidate.citationView ?? null,
    evidence: {
      id: packet.evidence.id, verifiedAt: packet.evidence.verifiedAt,
      promotionSequence: null, recordSha256: null,
    },
  };
}

async function route(request: IncomingMessage, response: ServerResponse, workspace: LocalWorkspace | undefined, packetReviews: readonly PacketReviewState[] | undefined, stackReports: ReviewStackReport[], archiveInventory?: ArchiveInventory, upgradeInventory?: UpgradeInventory, coverageReadiness?: CoverageReadiness, workspaceAcceptance?: ReviewWorkspaceAcceptance, lineageContinuity?: ReviewLineageContinuity, transitionHistory?: TransitionHistoryReview, bundleHistoryReadiness?: BundleHistoryReadiness): Promise<void> {
  securityHeaders(response);
  if (request.method !== "GET") { sendJson(response, 405, { error: "Read-only workspace: GET only" }); return; }
  if (!/^127\.0\.0\.1:\d+$/u.test(request.headers.host ?? "")) {
    sendJson(response, 421, { error: "Invalid local host" }); return;
  }
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  if (url.pathname === "/") { send(response, 200, "text/html; charset=utf-8", REVIEW_HTML); return; }
  if (url.pathname === "/styles.css") { send(response, 200, "text/css; charset=utf-8", REVIEW_STYLES); return; }
  if (url.pathname === "/app.js") { send(response, 200, "text/javascript; charset=utf-8", REVIEW_JAVASCRIPT); return; }
  if (url.pathname === "/api/review-bootstrap") {
    sendJson(response, 200, {
      version: 1,
      kind: "EvidenceForgeReviewBootstrap",
      review: reviewSummary(workspace, packetReviews),
      stackHistory: stackReports[0] ? { reports: stackReports } : null,
      archiveInventory: archiveInventory ?? null,
      upgradeInventory: upgradeInventory ?? null,
      coverageReadiness: coverageReadiness ?? null,
      workspaceAcceptance: workspaceAcceptance ?? null,
      lineageContinuity: lineageContinuity ?? null,
      transitionHistory: bundleHistoryReadiness ? null : transitionHistory ?? null,
      bundleHistoryReadiness: bundleHistoryReadiness ?? null,
    }); return;
  }
  if (url.pathname === "/api/archive-inventory") {
    if (!archiveInventory) { sendJson(response, 404, { error: "Archive inventory not configured" }); return; }
    sendJson(response, 200, archiveInventory); return;
  }
  if (url.pathname === "/api/upgrade-inventory") {
    if (!upgradeInventory) { sendJson(response, 404, { error: "Upgrade inventory not configured" }); return; }
    sendJson(response, 200, upgradeInventory); return;
  }
  if (url.pathname === "/api/coverage-readiness") {
    if (!coverageReadiness) { sendJson(response, 404, { error: "Combined coverage not configured" }); return; }
    sendJson(response, 200, coverageReadiness); return;
  }
  if (url.pathname === "/api/workspace-acceptance") {
    if (!workspaceAcceptance) { sendJson(response, 404, { error: "Workspace acceptance not configured" }); return; }
    sendJson(response, 200, workspaceAcceptance); return;
  }
  if (url.pathname === "/api/lineage-continuity") {
    if (!lineageContinuity) { sendJson(response, 404, { error: "Lineage continuity not configured" }); return; }
    sendJson(response, 200, lineageContinuity); return;
  }
  if (url.pathname === "/api/packet-transition-history") {
    if (!transitionHistory || bundleHistoryReadiness) { sendJson(response, 404, { error: "Standalone packet transition history not configured" }); return; }
    sendJson(response, 200, transitionHistory); return;
  }
  if (url.pathname === "/api/bundle-history-readiness") {
    if (!bundleHistoryReadiness) { sendJson(response, 404, { error: "Bundle/history readiness not configured" }); return; }
    sendJson(response, 200, bundleHistoryReadiness); return;
  }
  if (url.pathname === "/api/stack-report") {
    if (!stackReports[0]) { sendJson(response, 404, { error: "Stack report not configured" }); return; }
    sendJson(response, 200, stackReports[0]); return;
  }
  if (url.pathname === "/api/stack-history") {
    if (!stackReports[0]) { sendJson(response, 404, { error: "Stack report not configured" }); return; }
    sendJson(response, 200, { reports: stackReports }); return;
  }
  if (url.pathname === "/api/review") {
    sendJson(response, 200, reviewSummary(workspace, packetReviews)); return;
  }
  const match = /^\/api\/review\/([^/]+)$/u.exec(url.pathname);
  if (match?.[1]) {
    const candidateId = decodeURIComponent(match[1]);
    const packetReview = packetReviews?.find((review) => review.summary.id === candidateId);
    if (packetReview) { sendJson(response, 200, packetReview.detail); return; }
    if (!workspace) { sendJson(response, 404, { error: "Candidate not found" }); return; }
    const item = workspace.listReviewItems(MAX_REVIEW_ITEMS).find((entry) => entry.candidate.id === candidateId);
    if (!item) { sendJson(response, 404, { error: "Candidate not found" }); return; }
    const context = await sourceContext(item);
    sendJson(response, 200, {
      ...toSummary(item),
      attempts: workspace.listPromotionAttempts(candidateId, 100),
      context,
      provenance: sourceProvenance(workspace, item, context.integrity),
      citationView: item.candidate.citationView ?? null,
      evidence: item.evidence ? {
        id: item.evidence.id, verifiedAt: item.evidence.verifiedAt,
        promotionSequence: item.promotion?.sequence, recordSha256: item.promotion?.recordSha256,
      } : null,
    }); return;
  }
  sendJson(response, 404, { error: "Not found" });
}

function reviewSummary(workspace?: LocalWorkspace, packetReviews?: readonly PacketReviewState[]) {
  const items = packetReviews ? packetReviews.map((review) => review.summary) : workspace?.listReviewItems(MAX_REVIEW_ITEMS) ?? [];
  return {
    items: packetReviews ? items : (items as ReviewItem[]).map(toSummary),
    totals: {
      all: items.length,
      candidate: items.filter((item) => item.status === "candidate").length,
      rejected: items.filter((item) => item.status === "rejected").length,
      verified: items.filter((item) => item.status === "verified").length,
    },
    limited: Boolean(workspace && items.length === MAX_REVIEW_ITEMS),
  };
}

function toSummary(item: ReviewItem) {
  return {
    id: item.candidate.id,
    status: item.status,
    quote: item.candidate.selector.exact,
    prefix: item.candidate.selector.prefix,
    suffix: item.candidate.selector.suffix,
    observedAt: item.candidate.observedAt,
    availableAt: item.candidate.snapshot.availableAt,
    capturedAt: item.candidate.snapshot.capturedAt,
    sha256: item.candidate.snapshot.sha256,
    byteLength: item.candidate.snapshot.byteLength,
    mediaType: boundedDisplay(item.candidate.snapshot.mediaType, 256),
    source: displaySource(item.candidate.snapshot.sourceUri),
    failureCode: item.latestAttempt?.failureCode ?? null,
    failureMessage: item.latestAttempt?.failureMessage ?? null,
  };
}

function sourceProvenance(workspace: LocalWorkspace, item: ReviewItem, snapshotIntegrity: string) {
  if (sourceKind(item.candidate.snapshot.sourceUri) === "local") {
    return { kind: "local", integrity: snapshotIntegrity };
  }
  try {
    const captures = workspace.getWebCapturesForCandidate(item.candidate.id, 2);
    if (captures.length !== 1) {
      return { kind: "web", integrity: "failed", message: captures.length === 0
        ? "対応するWeb取得記録がありません。" : "対応するWeb取得記録を一意に特定できません。" };
    }
    const capture = captures[0];
    assertWebSourceCapture(capture);
    if (!isDeepStrictEqual(capture.snapshot, item.candidate.snapshot) || snapshotIntegrity !== "verified") {
      return { kind: "web", integrity: "failed", message: "Web取得記録と保存済み本文の整合性を確認できません。" };
    }
    return {
      kind: "web", integrity: "verified",
      requestedUrl: displaySource(capture.requestedUrl), canonicalUrl: displaySource(capture.canonicalUrl),
      redirectCount: capture.redirectChain.length, status: capture.status, retrievedAt: capture.retrievedAt,
      representation: {
        contentType: boundedDisplay(capture.representationHeaders["content-type"] ?? "application/octet-stream", 256),
        contentLanguage: capture.representationHeaders["content-language"]
          ? boundedDisplay(capture.representationHeaders["content-language"], 256) : null,
        contentEncoding: boundedDisplay(capture.representationHeaders["content-encoding"] ?? "identity", 256),
      },
      assurance: "integrity-checked-retained-snapshot",
    };
  } catch {
    return { kind: "web", integrity: "failed", message: "Web取得記録を安全に読み込めません。" };
  }
}

function sourceKind(value: string): "local" | "web" {
  try {
    const protocol = new URL(value).protocol;
    return protocol === "http:" || protocol === "https:" ? "web" : "local";
  } catch { return "local"; }
}

async function sourceContext(item: ReviewItem) {
  const snapshot = item.candidate.snapshot;
  let handle;
  try {
    handle = await open(snapshot.objectPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || info.size > MAX_CONTEXT_BYTES) throw new Error("Snapshot is unavailable or exceeds the review limit");
    const bytes = await handle.readFile();
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (digest !== snapshot.sha256 || bytes.byteLength !== snapshot.byteLength) throw new Error("Snapshot integrity check failed");
    const text = citationText(bytes, snapshot, item.candidate.citationView);
    const index = text.indexOf(item.candidate.selector.exact);
    if (index < 0) throw new Error("Exact quote is absent from the snapshot");
    return {
      integrity: "verified",
      before: text.slice(Math.max(0, index - 280), index),
      exact: item.candidate.selector.exact,
      after: text.slice(index + item.candidate.selector.exact.length, index + item.candidate.selector.exact.length + 280),
    };
  } catch {
    return { integrity: "failed", message: "保存済み出典の整合性を確認できません。" };
  } finally { await handle?.close(); }
}

function displaySource(value: string): string {
  try {
    const url = new URL(value);
    if (url.protocol === "file:") return "ローカルスナップショット";
    return boundedDisplay(`${url.origin}${url.pathname}`, 4096);
  } catch { return "保存済みスナップショット"; }
}

function boundedDisplay(value: string, maximumCharacters: number): string {
  return value.length <= maximumCharacters ? value : `${value.slice(0, maximumCharacters - 1)}…`;
}

function securityHeaders(response: ServerResponse): void {
  response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Cache-Control", "no-store");
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  send(response, status, "application/json; charset=utf-8", `${JSON.stringify(value)}\n`);
}
function send(response: ServerResponse, status: number, contentType: string, body: string): void {
  response.writeHead(status, { "Content-Type": contentType }); response.end(body);
}
async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => {
    if (error) reject(error);
    else resolve();
  }));
}
