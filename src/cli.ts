#!/usr/bin/env node
import { lstat, readFile } from "node:fs/promises";
import { option, options, pathOption, pathOptions, runCli } from "./cli-support.js";
import { createCliCapabilities } from "./capabilities.js";
import { compareCliCapabilities, loadCliCapabilities } from "./capability-compatibility.js";
import { persistedWebCapture, previewWebCaptureCitation, uniqueCitationFromPreview } from "./citation-preview.js";
import { PromotionError, type WebSourceCapture } from "./domain.js";
import { assertEvidenceCandidate } from "./evidence-envelope.js";
import { diagnosticError } from "./diagnostics.js";
import { createEvidencePacket, EvidencePacketError, verifyEvidencePacket } from "./evidence-packet.js";
import { appendEvidencePacketIndex, auditEvidencePacketCollection, createEvidencePacketIndex, verifyEvidencePacketCollectionAudit } from "./evidence-packet-collection.js";
import { appendEvidencePacketCollectionBundleBatch, createEvidencePacketCollectionBundle, loadEvidencePacketCollectionBundle } from "./evidence-packet-collection-bundle.js";
import { appendEvidencePacketCollectionLineageBundle, appendEvidencePacketsToCollectionLineageBundle, createEvidencePacketCollectionLineageBundle, loadEvidencePacketCollectionLineageBundle } from "./evidence-packet-collection-lineage-bundle.js";
import { auditEvidencePacketCollectionBundleTransition, verifyEvidencePacketCollectionTransitionAuditReceipt } from "./evidence-packet-collection-transition.js";
import { appendEvidencePacketTransitionHistoryIndex, createEvidencePacketTransitionHistoryIndex, loadEvidencePacketTransitionHistoryIndex } from "./evidence-packet-transition-history.js";
import { auditEvidencePacketTransitionHistoryCollection, verifyEvidencePacketTransitionHistoryAuditReceipt } from "./evidence-packet-transition-history-audit.js";
import { captureLocalCitation, promoteCandidate } from "./forge.js";
import { inspectPacketHead, PacketHeadInspectionError } from "./packet-head-inspection.js";
import { forgeLocalFile, parseLocalFileForgeArguments } from "./local-file-forge.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { parseQuickstartArguments, runQuickstart } from "./quickstart.js";
import { assertWebSourceCapture, captureWebSource, createCandidateFromWebCapture, WebCaptureError } from "./web-capture.js";
import { startReviewServer } from "./review-server.js";
import { LocalWorkspace } from "./workspace.js";

const arguments_ = process.argv.slice(2);
const HELP = `Usage:
  evidence-forge quickstart [--directory NEW_DIR]
  evidence-forge forge-local --source FILE (--exact TEXT | --exact-file FILE) --available-at ISO --directory NEW_DIR --promote-immediately
  evidence-forge capabilities
  evidence-forge compare-capabilities --previous FILE --expected-previous-sha256 SHA256 --current FILE --expected-current-sha256 SHA256 [--out NEW_FILE]
  evidence-forge capture --workspace DIR --source FILE --exact TEXT --available-at ISO [--database FILE] [--out NEW_FILE]
  evidence-forge promote --candidate FILE [--database FILE] [--out NEW_FILE]
  evidence-forge capture-web --workspace DIR --url URL [--database FILE] [--allow-private-addresses] [--out NEW_FILE]
  evidence-forge preview-citation --capture FILE --query TEXT --database FILE [--out NEW_FILE]
  evidence-forge cite-web --capture FILE (--exact TEXT | --query TEXT) --database FILE [--out NEW_FILE]
  evidence-forge export-packet --candidate FILE --evidence FILE --out NEW_FILE
  evidence-forge inspect-packet-head --packet FILE [--out NEW_FILE]
  evidence-forge verify-packet --packet FILE --expected-sha256 SHA256 [--out NEW_FILE]
  evidence-forge create-packet-index --packet FILE --expected-packet-sha256 SHA256 ... --out NEW_FILE
  evidence-forge append-packet-index --current-index FILE --current-index-sha256 SHA256 --packet FILE --expected-packet-sha256 SHA256 --out NEW_FILE
  evidence-forge audit-packet-collection --packet-index FILE --packet-index-sha256 SHA256 --packet FILE ... --out NEW_FILE
  evidence-forge verify-packet-collection --packet-index FILE --packet-index-sha256 SHA256 --packet-audit-receipt FILE --packet-audit-receipt-sha256 SHA256 [--out NEW_FILE]
  evidence-forge export-packet-collection-bundle --packet-index FILE --packet-index-sha256 SHA256 --packet-audit-receipt FILE --packet-audit-receipt-sha256 SHA256 --packet FILE ... --out NEW_FILE
  evidence-forge append-packet-collection-bundle --current-bundle FILE --current-bundle-sha256 SHA256 --packet FILE --expected-packet-sha256 SHA256 ... --out NEW_FILE
  evidence-forge verify-packet-collection-bundle --bundle FILE --expected-sha256 SHA256 [--out NEW_FILE]
  evidence-forge audit-packet-collection-bundle-transition --previous-bundle FILE --previous-bundle-sha256 SHA256 --next-bundle FILE --next-bundle-sha256 SHA256 --out NEW_FILE
  evidence-forge verify-packet-collection-transition --receipt FILE --expected-sha256 SHA256 [--out NEW_FILE]
  evidence-forge create-packet-transition-history --receipt FILE --expected-receipt-sha256 SHA256 ... --out NEW_FILE
  evidence-forge append-packet-transition-history --current-index FILE --current-index-sha256 SHA256 --receipt FILE --expected-receipt-sha256 SHA256 --out NEW_FILE
  evidence-forge verify-packet-transition-history --index FILE --expected-sha256 SHA256 [--out NEW_FILE]
  evidence-forge audit-packet-transition-history --index FILE --index-sha256 SHA256 --receipt FILE ... --out NEW_FILE
  evidence-forge verify-packet-transition-history-audit --audit-receipt FILE --expected-sha256 SHA256 [--out NEW_FILE]
  evidence-forge export-packet-collection-lineage --evidence-packet-bundle FILE --evidence-packet-bundle-sha256 SHA256 --packet-transition-history-index FILE --packet-transition-history-index-sha256 SHA256 --packet-transition-history-audit-receipt FILE --packet-transition-history-audit-receipt-sha256 SHA256 --receipt FILE --expected-receipt-sha256 SHA256 ... --out NEW_FILE
  evidence-forge append-packet-collection-lineage --current-lineage FILE --current-lineage-sha256 SHA256 --next-bundle FILE --next-bundle-sha256 SHA256 --transition-receipt FILE --transition-receipt-sha256 SHA256 --out NEW_FILE
  evidence-forge append-packets-to-collection-lineage --current-lineage FILE --current-lineage-sha256 SHA256 --packet FILE --expected-packet-sha256 SHA256 ... --out NEW_FILE
  evidence-forge verify-packet-collection-lineage --lineage FILE --expected-sha256 SHA256 [--out NEW_FILE]
  evidence-forge review (--database FILE | --evidence-packet FILE --evidence-packet-sha256 SHA256 | --evidence-packet-index FILE --evidence-packet-index-sha256 SHA256 --evidence-packet-audit-receipt FILE --evidence-packet-audit-receipt-sha256 SHA256 --evidence-packet FILE ... | --evidence-packet-bundle FILE --evidence-packet-bundle-sha256 SHA256 | --evidence-packet-lineage FILE --evidence-packet-lineage-sha256 SHA256) [--stack-report FILE ...] [--stack-signature FILE ... --trusted-public-key FILE ...] [--stack-bundle FILE (--trust-manifest FILE --trust-manifest-sha256 SHA256 [--trust-history FILE] | --trusted-key-id SHA256 ... | --trust-history FILE --trust-anchor-key-id SHA256 ... --trust-anchor-threshold N --trust-history-sha256 SHA256)] [--signature-threshold N] [--trust-valid-from ISO --trust-valid-until ISO] [--revoked-key-id SHA256 ...] [--release-index FILE --release-index-sha256 SHA256 --archive-audit-receipt FILE --archive-audit-receipt-sha256 SHA256] [--upgrade-history-index FILE --upgrade-history-index-sha256 SHA256 --upgrade-history-audit-receipt FILE --upgrade-history-audit-receipt-sha256 SHA256] [--workspace-acceptance-receipt FILE --workspace-acceptance-receipt-sha256 SHA256] [--lineage-continuity-receipt FILE --lineage-continuity-receipt-sha256 SHA256] [--packet-transition-history-index FILE --packet-transition-history-index-sha256 SHA256 --packet-transition-history-audit-receipt FILE --packet-transition-history-audit-receipt-sha256 SHA256] [--port PORT]`;

async function main(): Promise<void> {
  const command = arguments_[0];
  if (command === "quickstart") {
    const directory = parseQuickstartArguments(arguments_);
    process.stdout.write(`${JSON.stringify(await runQuickstart(directory), null, 2)}\n`);
    return;
  }
  if (command === "forge-local") {
    process.stdout.write(`${JSON.stringify(await forgeLocalFile(parseLocalFileForgeArguments(arguments_)), null, 2)}\n`);
    return;
  }
  if (command === "capabilities") {
    process.stdout.write(`${JSON.stringify(createCliCapabilities(), null, 2)}\n`);
    return;
  }
  if (command === "compare-capabilities") {
    const receipt = compareCliCapabilities(
      loadCliCapabilities(pathOption(arguments_, "previous"), option(arguments_, "expected-previous-sha256")),
      loadCliCapabilities(pathOption(arguments_, "current"), option(arguments_, "expected-current-sha256")),
    );
    await writeOutput(receipt);
    if (!receipt.versionPolicy.satisfied) process.exitCode = 3;
    else if (receipt.outcome === "breaking") process.exitCode = 2;
    return;
  }
  if (command === "capture") {
    await assertOutputAvailable();
    const candidate = await captureLocalCitation({
      workspace: pathOption(arguments_, "workspace"),
      sourcePath: pathOption(arguments_, "source"),
      exact: option(arguments_, "exact"),
      availableAt: option(arguments_, "available-at"),
    });
    if (arguments_.includes("--database")) {
      const workspace = new LocalWorkspace(pathOption(arguments_, "database"));
      try { workspace.saveCandidate(candidate); } finally { workspace.close(); }
    }
    await writeOutput(candidate);
    return;
  }
  if (command === "promote") {
    await assertOutputAvailable();
    const candidate = JSON.parse(await readFile(pathOption(arguments_, "candidate"), "utf8")) as unknown;
    try {
      assertEvidenceCandidate(candidate);
      if (arguments_.includes("--database")) {
        const workspace = new LocalWorkspace(pathOption(arguments_, "database"));
        try { await writeOutput(await workspace.promoteAndPersist(candidate)); } finally { workspace.close(); }
      } else {
        await writeOutput(await promoteCandidate(candidate));
      }
    } catch (error) {
      if (error instanceof PromotionError) throw diagnosticError(error.code, error.message, { cause: error });
      throw error;
    }
    return;
  }
  if (command === "capture-web") {
    await assertOutputAvailable();
    try {
      const capture = await captureWebSource({
        workspace: pathOption(arguments_, "workspace"), url: option(arguments_, "url"),
        ...(arguments_.includes("--allow-private-addresses") ? { transportPolicy: { allowPrivateAddresses: true } } : {}),
      });
      if (arguments_.includes("--database")) {
        const workspace = new LocalWorkspace(pathOption(arguments_, "database"));
        try { workspace.saveWebCapture(capture); } finally { workspace.close(); }
      }
      await writeOutput(capture);
    } catch (error) {
      if (error instanceof WebCaptureError) throw diagnosticError(error.code, error.message, { cause: error });
      throw error;
    }
    return;
  }
  if (command === "cite-web") {
    await assertOutputAvailable();
    try {
      const input = JSON.parse(await readFile(pathOption(arguments_, "capture"), "utf8")) as unknown;
      assertWebSourceCapture(input);
      const workspace = new LocalWorkspace(pathOption(arguments_, "database"));
      try {
        const persisted = persistedWebCapture(workspace, input);
        const candidate = await createCandidateFromWebCapture({ capture: persisted, exact: await citationInput(persisted) });
        workspace.saveCandidate(candidate);
        await writeOutput(candidate);
      } finally { workspace.close(); }
    } catch (error) {
      if (error instanceof WebCaptureError) throw diagnosticError(error.code, error.message, { cause: error });
      throw error;
    }
    return;
  }
  if (command === "preview-citation") {
    await assertOutputAvailable();
    try {
      const input = JSON.parse(await readFile(pathOption(arguments_, "capture"), "utf8")) as unknown;
      assertWebSourceCapture(input);
      const workspace = new LocalWorkspace(pathOption(arguments_, "database"));
      try {
        const persisted = persistedWebCapture(workspace, input);
        await writeOutput(await previewWebCaptureCitation({ capture: persisted, query: option(arguments_, "query") }));
      } finally { workspace.close(); }
    } catch (error) {
      if (error instanceof WebCaptureError) throw diagnosticError(error.code, error.message, { cause: error });
      throw error;
    }
    return;
  }
  if (command === "export-packet") {
    await assertOutputAvailable();
    try {
      const candidate = JSON.parse(await readFile(pathOption(arguments_, "candidate"), "utf8")) as unknown;
      const evidence = JSON.parse(await readFile(pathOption(arguments_, "evidence"), "utf8")) as unknown;
      await writeOutput(await createEvidencePacket(candidate, evidence));
    } catch (error) {
      if (error instanceof EvidencePacketError || error instanceof PromotionError) {
        throw diagnosticError(error.code, error.message, { cause: error });
      }
      throw error;
    }
    return;
  }
  if (command === "verify-packet") {
    await assertOutputAvailable();
    try {
      const packet = JSON.parse(await readFile(pathOption(arguments_, "packet"), "utf8")) as unknown;
      await writeOutput(await verifyEvidencePacket(packet, option(arguments_, "expected-sha256")));
    } catch (error) {
      if (error instanceof EvidencePacketError || error instanceof PromotionError) {
        throw diagnosticError(error.code, error.message, { cause: error });
      }
      throw error;
    }
    return;
  }
  if (command === "inspect-packet-head") {
    await assertOutputAvailable();
    try {
      await writeOutput(await inspectPacketHead(pathOption(arguments_, "packet")));
    } catch (error) {
      if (error instanceof PacketHeadInspectionError) throw diagnosticError(error.code, error.message, { cause: error });
      throw error;
    }
    return;
  }
  if (command === "create-packet-index") {
    await assertOutputAvailable();
    const index = await createEvidencePacketIndex({
      packetPaths: pathOptions(arguments_, "packet"),
      expectedPacketSha256s: options(arguments_, "expected-packet-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ indexSha256: index.integrity.indexSha256, packetCount: index.entries.length })}\n`);
    return;
  }
  if (command === "append-packet-index") {
    await assertOutputAvailable();
    const index = await appendEvidencePacketIndex({
      currentIndexPath: pathOption(arguments_, "current-index"),
      expectedCurrentIndexSha256: option(arguments_, "current-index-sha256"),
      packetPath: pathOption(arguments_, "packet"),
      expectedPacketSha256: option(arguments_, "expected-packet-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ indexSha256: index.integrity.indexSha256, packetCount: index.entries.length })}\n`);
    return;
  }
  if (command === "audit-packet-collection") {
    await assertOutputAvailable();
    const { receipt } = await auditEvidencePacketCollection({
      indexPath: pathOption(arguments_, "packet-index"),
      expectedIndexSha256: option(arguments_, "packet-index-sha256"),
      packetPaths: pathOptions(arguments_, "packet"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ auditSha256: receipt.integrity.auditSha256, verifiedPacketCount: receipt.collection.verifiedPacketCount })}\n`);
    return;
  }
  if (command === "verify-packet-collection") {
    await assertOutputAvailable();
    await writeOutput(verifyEvidencePacketCollectionAudit({
      indexPath: pathOption(arguments_, "packet-index"),
      expectedIndexSha256: option(arguments_, "packet-index-sha256"),
      auditReceiptPath: pathOption(arguments_, "packet-audit-receipt"),
      expectedAuditSha256: option(arguments_, "packet-audit-receipt-sha256"),
    }));
    return;
  }
  if (command === "export-packet-collection-bundle") {
    await assertOutputAvailable();
    const bundle = await createEvidencePacketCollectionBundle({
      indexPath: pathOption(arguments_, "packet-index"),
      expectedIndexSha256: option(arguments_, "packet-index-sha256"),
      auditReceiptPath: pathOption(arguments_, "packet-audit-receipt"),
      expectedAuditSha256: option(arguments_, "packet-audit-receipt-sha256"),
      packetPaths: pathOptions(arguments_, "packet"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ bundleSha256: bundle.integrity.bundleSha256, packetCount: bundle.packets.length })}\n`);
    return;
  }
  if (command === "verify-packet-collection-bundle") {
    await assertOutputAvailable();
    const { verification } = await loadEvidencePacketCollectionBundle(
      pathOption(arguments_, "bundle"), option(arguments_, "expected-sha256"),
    );
    await writeOutput(verification);
    return;
  }
  if (command === "append-packet-collection-bundle") {
    await assertOutputAvailable();
    const bundle = await appendEvidencePacketCollectionBundleBatch({
      currentBundlePath: pathOption(arguments_, "current-bundle"),
      expectedCurrentBundleSha256: option(arguments_, "current-bundle-sha256"),
      packetPaths: pathOptions(arguments_, "packet"),
      expectedPacketSha256s: options(arguments_, "expected-packet-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ bundleSha256: bundle.integrity.bundleSha256, packetCount: bundle.packets.length })}\n`);
    return;
  }
  if (command === "audit-packet-collection-bundle-transition") {
    await assertOutputAvailable();
    const receipt = await auditEvidencePacketCollectionBundleTransition({
      previousBundlePath: pathOption(arguments_, "previous-bundle"),
      expectedPreviousBundleSha256: option(arguments_, "previous-bundle-sha256"),
      nextBundlePath: pathOption(arguments_, "next-bundle"),
      expectedNextBundleSha256: option(arguments_, "next-bundle-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ auditSha256: receipt.integrity.auditSha256, appendedPacketCount: receipt.append.packetCount })}\n`);
    return;
  }
  if (command === "verify-packet-collection-transition") {
    await assertOutputAvailable();
    await writeOutput(verifyEvidencePacketCollectionTransitionAuditReceipt(
      pathOption(arguments_, "receipt"), option(arguments_, "expected-sha256"),
    ));
    return;
  }
  if (command === "create-packet-transition-history") {
    await assertOutputAvailable();
    const index = await createEvidencePacketTransitionHistoryIndex({
      receiptPaths: pathOptions(arguments_, "receipt"),
      expectedReceiptSha256s: options(arguments_, "expected-receipt-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ indexSha256: index.integrity.indexSha256, transitionCount: index.entries.length })}\n`);
    return;
  }
  if (command === "append-packet-transition-history") {
    await assertOutputAvailable();
    const index = await appendEvidencePacketTransitionHistoryIndex({
      currentIndexPath: pathOption(arguments_, "current-index"),
      expectedCurrentIndexSha256: option(arguments_, "current-index-sha256"),
      receiptPath: pathOption(arguments_, "receipt"),
      expectedReceiptSha256: option(arguments_, "expected-receipt-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ indexSha256: index.integrity.indexSha256, transitionCount: index.entries.length })}\n`);
    return;
  }
  if (command === "verify-packet-transition-history") {
    await assertOutputAvailable();
    const index = loadEvidencePacketTransitionHistoryIndex(
      pathOption(arguments_, "index"), option(arguments_, "expected-sha256"),
    );
    await writeOutput({
      version: 1, kind: "EvidenceForgeEvidencePacketTransitionHistoryVerification", outcome: "verified",
      transitionCount: index.entries.length,
      firstBundleSha256: index.entries[0]?.previousBundleSha256,
      latestBundleSha256: index.entries.at(-1)?.nextBundleSha256,
      initialPacketCount: index.entries[0]?.previousPacketCount,
      latestPacketCount: index.entries.at(-1)?.nextPacketCount,
      indexSha256: index.integrity.indexSha256,
      timestampAttested: false,
    });
    return;
  }
  if (command === "audit-packet-transition-history") {
    await assertOutputAvailable();
    const receipt = await auditEvidencePacketTransitionHistoryCollection({
      indexPath: pathOption(arguments_, "index"),
      expectedIndexSha256: option(arguments_, "index-sha256"),
      receiptPaths: pathOptions(arguments_, "receipt"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ auditSha256: receipt.integrity.auditSha256, transitionCount: receipt.history.transitionCount })}\n`);
    return;
  }
  if (command === "verify-packet-transition-history-audit") {
    await assertOutputAvailable();
    await writeOutput(verifyEvidencePacketTransitionHistoryAuditReceipt(
      pathOption(arguments_, "audit-receipt"), option(arguments_, "expected-sha256"),
    ));
    return;
  }
  if (command === "export-packet-collection-lineage") {
    await assertOutputAvailable();
    const lineage = await createEvidencePacketCollectionLineageBundle({
      collectionBundlePath: pathOption(arguments_, "evidence-packet-bundle"),
      expectedCollectionBundleSha256: option(arguments_, "evidence-packet-bundle-sha256"),
      historyIndexPath: pathOption(arguments_, "packet-transition-history-index"),
      expectedHistoryIndexSha256: option(arguments_, "packet-transition-history-index-sha256"),
      historyAuditReceiptPath: pathOption(arguments_, "packet-transition-history-audit-receipt"),
      expectedHistoryAuditSha256: option(arguments_, "packet-transition-history-audit-receipt-sha256"),
      transitionReceiptPaths: pathOptions(arguments_, "receipt"),
      expectedTransitionReceiptSha256s: options(arguments_, "expected-receipt-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ lineageSha256: lineage.integrity.lineageSha256, transitionCount: lineage.transitions.length })}\n`);
    return;
  }
  if (command === "verify-packet-collection-lineage") {
    await assertOutputAvailable();
    const { verification } = await loadEvidencePacketCollectionLineageBundle(
      pathOption(arguments_, "lineage"), option(arguments_, "expected-sha256"),
    );
    await writeOutput(verification);
    return;
  }
  if (command === "append-packet-collection-lineage") {
    await assertOutputAvailable();
    const lineage = await appendEvidencePacketCollectionLineageBundle({
      currentLineagePath: pathOption(arguments_, "current-lineage"),
      expectedCurrentLineageSha256: option(arguments_, "current-lineage-sha256"),
      nextCollectionBundlePath: pathOption(arguments_, "next-bundle"),
      expectedNextCollectionBundleSha256: option(arguments_, "next-bundle-sha256"),
      transitionReceiptPath: pathOption(arguments_, "transition-receipt"),
      expectedTransitionReceiptSha256: option(arguments_, "transition-receipt-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ lineageSha256: lineage.integrity.lineageSha256, transitionCount: lineage.transitions.length })}\n`);
    return;
  }
  if (command === "append-packets-to-collection-lineage") {
    await assertOutputAvailable();
    const lineage = await appendEvidencePacketsToCollectionLineageBundle({
      currentLineagePath: pathOption(arguments_, "current-lineage"),
      expectedCurrentLineageSha256: option(arguments_, "current-lineage-sha256"),
      packetPaths: pathOptions(arguments_, "packet"),
      expectedPacketSha256s: options(arguments_, "expected-packet-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ lineageSha256: lineage.integrity.lineageSha256, packetCount: lineage.collectionBundle.packets.length, transitionCount: lineage.transitions.length })}\n`);
    return;
  }
  if (command === "review") {
    if (!arguments_.includes("--database") && !arguments_.includes("--evidence-packet") &&
        !arguments_.includes("--evidence-packet-bundle") && !arguments_.includes("--evidence-packet-lineage")) {
      throw new Error("Review requires a workspace database, an Evidence packet, or an Evidence packet collection");
    }
    const packetCollection = arguments_.includes("--evidence-packet-index");
    const server = await startReviewServer({
      ...(arguments_.includes("--database") ? { databasePath: pathOption(arguments_, "database") } : {}),
      ...(!packetCollection && arguments_.includes("--evidence-packet") ? { evidencePacketPath: pathOption(arguments_, "evidence-packet") } : {}),
      ...(!packetCollection && arguments_.includes("--evidence-packet-sha256") ? { evidencePacketSha256: option(arguments_, "evidence-packet-sha256") } : {}),
      ...(packetCollection ? {
        evidencePacketPaths: pathOptions(arguments_, "evidence-packet"),
        evidencePacketIndexPath: pathOption(arguments_, "evidence-packet-index"),
        evidencePacketIndexSha256: option(arguments_, "evidence-packet-index-sha256"),
        evidencePacketAuditReceiptPath: pathOption(arguments_, "evidence-packet-audit-receipt"),
        evidencePacketAuditReceiptSha256: option(arguments_, "evidence-packet-audit-receipt-sha256"),
      } : {}),
      ...(arguments_.includes("--evidence-packet-bundle") ? {
        evidencePacketBundlePath: pathOption(arguments_, "evidence-packet-bundle"),
        evidencePacketBundleSha256: option(arguments_, "evidence-packet-bundle-sha256"),
      } : {}),
      ...(arguments_.includes("--evidence-packet-lineage") ? {
        evidencePacketLineagePath: pathOption(arguments_, "evidence-packet-lineage"),
        evidencePacketLineageSha256: option(arguments_, "evidence-packet-lineage-sha256"),
      } : {}),
      ...(arguments_.includes("--port") ? { port: Number(option(arguments_, "port")) } : {}),
      ...(arguments_.includes("--stack-report") ? { stackReportPaths: pathOptions(arguments_, "stack-report") } : {}),
      ...(arguments_.includes("--stack-bundle") ? { stackBundlePath: pathOption(arguments_, "stack-bundle") } : {}),
      ...(arguments_.includes("--stack-signature") ? { stackSignaturePaths: pathOptions(arguments_, "stack-signature") } : {}),
      ...(arguments_.includes("--trusted-public-key") ? { trustedPublicKeyPaths: pathOptions(arguments_, "trusted-public-key") } : {}),
      ...(arguments_.includes("--trusted-key-id") ? { trustedKeyIds: options(arguments_, "trusted-key-id") } : {}),
      ...(arguments_.includes("--trust-history") ? { trustHistoryPath: pathOption(arguments_, "trust-history") } : {}),
      ...(arguments_.includes("--trust-anchor-key-id") ? { trustAnchorKeyIds: options(arguments_, "trust-anchor-key-id") } : {}),
      ...(arguments_.includes("--trust-anchor-threshold") ? { trustAnchorThreshold: Number(option(arguments_, "trust-anchor-threshold")) } : {}),
      ...(arguments_.includes("--trust-history-sha256") ? { trustHistorySha256: option(arguments_, "trust-history-sha256") } : {}),
      ...(arguments_.includes("--trust-manifest") ? { trustManifestPath: pathOption(arguments_, "trust-manifest") } : {}),
      ...(arguments_.includes("--trust-manifest-sha256") ? { trustManifestSha256: option(arguments_, "trust-manifest-sha256") } : {}),
      ...(arguments_.includes("--signature-threshold") ? { signatureThreshold: Number(option(arguments_, "signature-threshold")) } : {}),
      ...(arguments_.includes("--trust-valid-from") ? { trustValidFrom: option(arguments_, "trust-valid-from") } : {}),
      ...(arguments_.includes("--trust-valid-until") ? { trustValidUntil: option(arguments_, "trust-valid-until") } : {}),
      ...(arguments_.includes("--revoked-key-id") ? { revokedKeyIds: options(arguments_, "revoked-key-id") } : {}),
      ...(arguments_.includes("--release-index") ? { releaseIndexPath: pathOption(arguments_, "release-index") } : {}),
      ...(arguments_.includes("--release-index-sha256") ? { releaseIndexSha256: option(arguments_, "release-index-sha256") } : {}),
      ...(arguments_.includes("--archive-audit-receipt") ? { archiveAuditReceiptPath: pathOption(arguments_, "archive-audit-receipt") } : {}),
      ...(arguments_.includes("--archive-audit-receipt-sha256") ? { archiveAuditReceiptSha256: option(arguments_, "archive-audit-receipt-sha256") } : {}),
      ...(arguments_.includes("--upgrade-history-index") ? { upgradeHistoryIndexPath: pathOption(arguments_, "upgrade-history-index") } : {}),
      ...(arguments_.includes("--upgrade-history-index-sha256") ? { upgradeHistoryIndexSha256: option(arguments_, "upgrade-history-index-sha256") } : {}),
      ...(arguments_.includes("--upgrade-history-audit-receipt") ? { upgradeHistoryAuditReceiptPath: pathOption(arguments_, "upgrade-history-audit-receipt") } : {}),
      ...(arguments_.includes("--upgrade-history-audit-receipt-sha256") ? { upgradeHistoryAuditReceiptSha256: option(arguments_, "upgrade-history-audit-receipt-sha256") } : {}),
      ...(arguments_.includes("--workspace-acceptance-receipt") ? { workspaceAcceptanceReceiptPath: pathOption(arguments_, "workspace-acceptance-receipt") } : {}),
      ...(arguments_.includes("--workspace-acceptance-receipt-sha256") ? { workspaceAcceptanceReceiptSha256: option(arguments_, "workspace-acceptance-receipt-sha256") } : {}),
      ...(arguments_.includes("--lineage-continuity-receipt") ? { lineageContinuityReceiptPath: pathOption(arguments_, "lineage-continuity-receipt") } : {}),
      ...(arguments_.includes("--lineage-continuity-receipt-sha256") ? { lineageContinuityReceiptSha256: option(arguments_, "lineage-continuity-receipt-sha256") } : {}),
      ...(arguments_.includes("--packet-transition-history-index") ? { packetTransitionHistoryIndexPath: pathOption(arguments_, "packet-transition-history-index") } : {}),
      ...(arguments_.includes("--packet-transition-history-index-sha256") ? { packetTransitionHistoryIndexSha256: option(arguments_, "packet-transition-history-index-sha256") } : {}),
      ...(arguments_.includes("--packet-transition-history-audit-receipt") ? { packetTransitionHistoryAuditReceiptPath: pathOption(arguments_, "packet-transition-history-audit-receipt") } : {}),
      ...(arguments_.includes("--packet-transition-history-audit-receipt-sha256") ? { packetTransitionHistoryAuditReceiptSha256: option(arguments_, "packet-transition-history-audit-receipt-sha256") } : {}),
    });
    process.stdout.write(`Review Workspace: ${server.url}\nPress Ctrl+C to stop.\n`);
    await new Promise<void>((resolveStop) => {
      process.once("SIGINT", () => { void server.close().then(resolveStop); });
      process.once("SIGTERM", () => { void server.close().then(resolveStop); });
    });
    return;
  }
  throw new Error("Unknown or missing command; run with --help for usage");
}

async function writeOutput(value: unknown): Promise<void> {
  const json = `${JSON.stringify(value, null, 2)}\n`;
  const output = arguments_.includes("--out") ? pathOption(arguments_, "out") : undefined;
  if (output) await writePrivateFileExclusive(output, json);
  else process.stdout.write(json);
}

async function citationInput(capture: WebSourceCapture): Promise<string> {
  const hasExact = arguments_.includes("--exact");
  const hasQuery = arguments_.includes("--query");
  if (hasExact === hasQuery) {
    throw new WebCaptureError("CITATION_INPUT_INVALID", "Specify exactly one of --exact or --query");
  }
  if (hasExact) return option(arguments_, "exact");
  return uniqueCitationFromPreview(await previewWebCaptureCitation({ capture, query: option(arguments_, "query") }));
}

async function assertOutputAvailable(): Promise<void> {
  if (!arguments_.includes("--out")) return;
  const output = pathOption(arguments_, "out");
  try {
    await lstat(output);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error("Output already exists");
}

await runCli(main, {
  arguments: arguments_, help: HELP,
  pathOptions: ["directory", "workspace", "source", "out", "candidate", "evidence", "packet", "packet-index", "packet-audit-receipt", "bundle", "lineage", "current-lineage", "next-bundle", "transition-receipt", "current-index", "evidence-packet", "evidence-packet-index", "evidence-packet-audit-receipt", "evidence-packet-bundle", "evidence-packet-lineage", "capture", "database", "stack-report", "stack-signature", "trusted-public-key", "stack-bundle", "trust-history", "trust-manifest", "release-index", "archive-audit-receipt", "upgrade-history-index", "upgrade-history-audit-receipt", "workspace-acceptance-receipt", "lineage-continuity-receipt", "packet-transition-history-index", "packet-transition-history-audit-receipt", "previous", "current"],
  errorPrefix: "Evidence Forge failed",
});
