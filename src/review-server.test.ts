import { mkdtemp, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { captureLocalCitation, promoteCandidate } from "./forge.js";
import { startReviewServer } from "./review-server.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { signStackReport } from "./stack-signature.js";
import { createStackReviewBundle } from "./stack-review-bundle.js";
import { appendTrustRotation } from "./trust-rotation.js";
import { createManualTrustManifest } from "./trust-manifest.js";
import { LocalWorkspace } from "./workspace.js";
import type { EvidenceCandidate, WebSourceCapture } from "./domain.js";
import { createHtmlCitationView } from "./html-citation-view.js";
import { createEvidencePacket } from "./evidence-packet.js";
import { auditEvidencePacketCollection, createEvidencePacketIndex } from "./evidence-packet-collection.js";
import { createEvidencePacketCollectionBundle } from "./evidence-packet-collection-bundle.js";
import Ajv2020Import from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";

const roots: string[] = [];
const servers: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(servers.splice(0).map(async (server) => { await server.close(); }));
  await Promise.all(roots.splice(0).map(async (root) => { await rm(root, { recursive: true, force: true }); }));
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "evidence-review-"));
  roots.push(root);
  const sourcePath = join(root, "source.txt");
  await writeFile(sourcePath, "Before context. A uniquely reviewable fact. After context.");
  const candidate = await captureLocalCitation({
    workspace: join(root, "objects"), sourcePath, exact: "A uniquely reviewable fact.",
    availableAt: "2026-07-12T00:00:00.000Z", now: () => new Date("2026-07-12T01:00:00.000Z"),
  });
  return { root, sourcePath, candidate, databasePath: join(root, "workspace.sqlite") };
}

function webFixture(candidate: EvidenceCandidate): { candidate: EvidenceCandidate; capture: WebSourceCapture } {
  const snapshot = {
    ...candidate.snapshot,
    mediaType: "text/html; charset=utf-8", sourceUri: "https://example.com/final?private=hidden",
    availableAt: candidate.observedAt,
    capturedAt: candidate.observedAt,
  };
  const citationView = createHtmlCitationView(
    Buffer.from("Before context. A uniquely reviewable fact. After context."), snapshot.sha256,
  ).view;
  return {
    candidate: { ...candidate, id: `web_${candidate.id}`, snapshot, citationView },
    capture: {
      kind: "WebSourceCapture", id: `capture_${candidate.id}`, snapshot,
      wireResponse: {
        sha256: snapshot.sha256, byteLength: snapshot.byteLength,
        objectPath: snapshot.objectPath, contentEncoding: "identity",
      },
      requestedUrl: "https://example.com/start?token=hidden",
      canonicalUrl: snapshot.sourceUri,
      redirectChain: [{
        url: "https://example.com/start?token=hidden", status: 302,
        location: "/final?private=hidden",
      }],
      status: 200,
      representationHeaders: { "content-type": snapshot.mediaType, "content-language": "ja" },
      retrievedAt: snapshot.capturedAt, availableAt: snapshot.availableAt,
      availabilityBasis: "successful-http-response-completed",
    },
  };
}

async function transitionHistoryFixture(root: string, options: { latestBundleSha256?: string; prefix?: string } = {}) {
  const entryPayload = {
    sequence: 1,
    transitionAuditSha256: "3".repeat(64),
    previousBundleSha256: "1".repeat(64),
    nextBundleSha256: options.latestBundleSha256 ?? "2".repeat(64),
    previousIndexSha256: "4".repeat(64),
    nextIndexSha256: "5".repeat(64),
    previousPacketCount: 1,
    nextPacketCount: 2,
    appendedPacketCount: 1,
    previousEntrySha256: null,
  };
  const indexPayload = {
    version: 1,
    kind: "EvidenceForgeEvidencePacketTransitionHistoryIndex",
    entries: [{ ...entryPayload, entrySha256: canonicalJsonSha256(entryPayload) }],
    assurance: { timestamp: "not-attested" },
  };
  const index = { ...indexPayload, integrity: { algorithm: "sha256-jcs", indexSha256: canonicalJsonSha256(indexPayload) } };
  const auditPayload = {
    version: 1,
    kind: "EvidenceForgeEvidencePacketTransitionHistoryAuditReceipt",
    outcome: "verified",
    history: { indexSha256: index.integrity.indexSha256, transitionCount: 1 },
    coverage: {
      initialBundleSha256: entryPayload.previousBundleSha256,
      latestBundleSha256: entryPayload.nextBundleSha256,
      initialPacketCount: 1,
      latestPacketCount: 2,
      firstTransitionAuditSha256: entryPayload.transitionAuditSha256,
      lastTransitionAuditSha256: entryPayload.transitionAuditSha256,
    },
    assurance: { timestamp: "not-attested" },
  };
  const audit = { ...auditPayload, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(auditPayload) } };
  const prefix = options.prefix ?? "transition-history";
  const indexPath = join(root, `${prefix}.json`), auditPath = join(root, `${prefix}-audit.json`);
  await writeFile(indexPath, JSON.stringify(index));
  await writeFile(auditPath, JSON.stringify(audit));
  return { index, audit, indexPath, auditPath };
}

describe("Review Workspace", () => {
  it("verifies a pinned packet transition history before exposing its bounded projection", async () => {
    const { root, databasePath } = await fixture();
    new LocalWorkspace(databasePath).close();
    const history = await transitionHistoryFixture(root);
    const server = await startReviewServer({
      databasePath,
      packetTransitionHistoryIndexPath: history.indexPath,
      packetTransitionHistoryIndexSha256: history.index.integrity.indexSha256,
      packetTransitionHistoryAuditReceiptPath: history.auditPath,
      packetTransitionHistoryAuditReceiptSha256: history.audit.integrity.auditSha256,
    });
    servers.push(server);
    const bootstrap = await (await fetch(`${server.url}/api/review-bootstrap`)).json() as Record<string, unknown>;
    expect(bootstrap.transitionHistory).toEqual({
      version: 1,
      kind: "EvidenceForgeReviewPacketTransitionHistory",
      outcome: "verified",
      transitionCount: 1,
      initialPacketCount: 1,
      latestPacketCount: 2,
      initialBundleSha256: "1".repeat(64),
      latestBundleSha256: "2".repeat(64),
      collectionReaudited: false,
      timestampAttested: false,
    });
    expect(JSON.stringify(bootstrap)).not.toContain(root);
    const schema = JSON.parse(await readFile(new URL("../schemas/review-bootstrap.schema.json", import.meta.url), "utf8")) as AnySchema;
    const Ajv2020 = Ajv2020Import.default;
    expect(new Ajv2020({ strict: true }).compile(schema)(bootstrap)).toBe(true);
    expect(await (await fetch(`${server.url}/app.js`)).text()).toContain("元ファイルの再監査");
  });

  it("rejects partial and mismatched packet transition history configuration before listening", async () => {
    const { root, databasePath } = await fixture();
    const history = await transitionHistoryFixture(root);
    await expect(startReviewServer({ databasePath, packetTransitionHistoryIndexPath: history.indexPath }))
      .rejects.toThrow("requires an index");
    const unsigned = {
      version: history.audit.version,
      kind: history.audit.kind,
      outcome: history.audit.outcome,
      history: { ...history.audit.history, indexSha256: "9".repeat(64) },
      coverage: history.audit.coverage,
      assurance: history.audit.assurance,
    };
    const mismatched = { ...unsigned, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(unsigned) } };
    const mismatchedPath = join(root, "mismatched-history-audit.json");
    await writeFile(mismatchedPath, JSON.stringify(mismatched));
    await expect(startReviewServer({
      databasePath,
      packetTransitionHistoryIndexPath: history.indexPath,
      packetTransitionHistoryIndexSha256: history.index.integrity.indexSha256,
      packetTransitionHistoryAuditReceiptPath: mismatchedPath,
      packetTransitionHistoryAuditReceiptSha256: mismatched.integrity.auditSha256,
    })).rejects.toThrow("does not match the pinned history index");
  });

  it("shows verified source context and append-only attempts without filesystem paths", async () => {
    const { root, candidate, databasePath } = await fixture();
    const workspace = new LocalWorkspace(databasePath);
    const rejected = { ...candidate, selector: { ...candidate.selector, prefix: "forged" } };
    await expect(workspace.promoteAndPersist(rejected, () => new Date("2026-07-12T02:00:00.000Z")))
      .rejects.toMatchObject({ code: "SELECTOR_CONTEXT_MISMATCH" });
    const corrected = { ...candidate, id: `${candidate.id}_corrected` };
    workspace.saveCandidate(corrected, new Date("2026-07-12T02:30:00.000Z"));
    await workspace.promoteAndPersist(corrected, () => new Date("2026-07-12T03:00:00.000Z"));
    workspace.close();

    const server = await startReviewServer({ databasePath });
    servers.push(server);
    const summaryResponse = await fetch(`${server.url}/api/review`);
    expect(summaryResponse.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(await (await fetch(`${server.url}/app.js`)).text()).toContain("classList.remove('empty-detail')");
    const summary = await summaryResponse.json() as { totals: Record<string, number>; items: Array<Record<string, unknown>> };
    expect(summary.totals).toMatchObject({ all: 2, rejected: 1, verified: 1 });
    expect(JSON.stringify(summary)).not.toContain(root);
    const bootstrap = await (await fetch(`${server.url}/api/review-bootstrap`)).json() as Record<string, unknown>;
    expect(bootstrap).toMatchObject({
      version: 1,
      kind: "EvidenceForgeReviewBootstrap",
      review: summary,
      stackHistory: null,
      archiveInventory: null,
      upgradeInventory: null,
      coverageReadiness: null,
      workspaceAcceptance: null,
      lineageContinuity: null,
      transitionHistory: null,
      bundleHistoryReadiness: null,
    });
    const bootstrapSchema = await readFile(new URL("../schemas/review-bootstrap.schema.json", import.meta.url), "utf8");
    expect(bootstrapSchema).not.toContain("sourceKind");
    expect(JSON.stringify(bootstrap)).not.toContain(root);

    const detail = await (await fetch(`${server.url}/api/review/${encodeURIComponent(corrected.id)}`)).json() as {
      context: { integrity: string; exact: string }; attempts: Array<{ outcome: string }>; evidence: unknown;
    };
    expect(detail.context).toMatchObject({ integrity: "verified", exact: corrected.selector.exact });
    expect(detail.attempts[0]?.outcome).toBe("verified");
    expect(detail.evidence).not.toBeNull();
  });

  it("explains empty state and fails source integrity closed", async () => {
    const empty = await fixture();
    new LocalWorkspace(empty.databasePath).close();
    const emptyServer = await startReviewServer({ databasePath: empty.databasePath });
    servers.push(emptyServer);
    const html = await (await fetch(emptyServer.url)).text();
    expect(html).toContain("確認する項目を選択");
    expect((await (await fetch(`${emptyServer.url}/api/review`)).json() as { totals: { all: number } }).totals.all).toBe(0);

    const populated = await fixture();
    const workspace = new LocalWorkspace(populated.databasePath);
    workspace.saveCandidate(populated.candidate);
    workspace.close();
    await writeFile(populated.candidate.snapshot.objectPath, "tampered");
    const server = await startReviewServer({ databasePath: populated.databasePath });
    servers.push(server);
    const detail = await (await fetch(`${server.url}/api/review/${encodeURIComponent(populated.candidate.id)}`)).json() as { context: { integrity: string } };
    expect(detail.context.integrity).toBe("failed");
    expect(JSON.stringify(detail)).not.toContain(populated.root);

    const replacement = join(populated.root, "replacement.txt");
    await writeFile(replacement, "Before context. A uniquely reviewable fact. After context.");
    await unlink(populated.candidate.snapshot.objectPath);
    await symlink(replacement, populated.candidate.snapshot.objectPath);
    const symlinkDetail = await (await fetch(`${server.url}/api/review/${encodeURIComponent(populated.candidate.id)}`)).json() as {
      context: { integrity: string; message: string };
    };
    expect(symlinkDetail.context).toEqual({ integrity: "failed", message: "保存済み出典の整合性を確認できません。" });
    expect(JSON.stringify(symlinkDetail)).not.toContain(populated.root);
  });

  it("reviews an externally pinned Evidence packet without a database or path leakage", async () => {
    const { root, candidate } = await fixture();
    const evidence = await promoteCandidate(candidate, () => new Date("2026-07-12T02:00:00.000Z"));
    const packet = await createEvidencePacket(candidate, evidence);
    const packetPath = join(root, "evidence-packet.json");
    await writeFile(packetPath, JSON.stringify(packet), { mode: 0o600 });

    const server = await startReviewServer({
      evidencePacketPath: packetPath, evidencePacketSha256: packet.integrity.packetSha256,
    });
    servers.push(server);
    const bootstrap = await (await fetch(`${server.url}/api/review-bootstrap`)).json() as {
      review: { totals: Record<string, number>; items: Array<{ id: string; source: string }> };
    };
    expect(bootstrap.review.totals).toEqual({ all: 1, candidate: 0, rejected: 0, verified: 1 });
    expect(bootstrap.review.items[0]).toMatchObject({
      id: candidate.id, source: "持ち運び用の検証済み記録",
    });
    const detail = await (await fetch(`${server.url}/api/review/${encodeURIComponent(candidate.id)}`)).json() as {
      context: { integrity: string; exact: string };
      provenance: { kind: string; packetSha256: string; timestampAttested: boolean };
      evidence: { id: string };
    };
    expect(detail).toMatchObject({
      context: { integrity: "verified", exact: candidate.selector.exact },
      provenance: {
        kind: "packet", packetSha256: packet.integrity.packetSha256, timestampAttested: false,
      },
      evidence: { id: evidence.id },
    });
    const packetReviewSchema = JSON.parse(await readFile(
      new URL("../schemas/review-evidence-packet.schema.json", import.meta.url), "utf8",
    )) as { additionalProperties: boolean; required: string[] };
    expect(Object.keys(detail).sort()).toEqual([...packetReviewSchema.required].sort());
    expect(packetReviewSchema.additionalProperties).toBe(false);
    expect(JSON.stringify({ bootstrap, detail })).not.toContain(root);
    expect(JSON.stringify({ bootstrap, detail })).not.toContain("file://");

    expect(await (await fetch(`${server.url}/app.js`)).text()).toContain("内容と照合値が一致");
  });

  it("rejects incomplete, mixed, and mutated packet review before listener startup", async () => {
    const { root, candidate, databasePath } = await fixture();
    const evidence = await promoteCandidate(candidate, () => new Date("2026-07-12T02:00:00.000Z"));
    const packet = await createEvidencePacket(candidate, evidence);
    const packetPath = join(root, "evidence-packet.json");
    await writeFile(packetPath, JSON.stringify(packet), { mode: 0o600 });
    await expect(startReviewServer({ evidencePacketPath: packetPath }))
      .rejects.toThrow("requires a packet and expected SHA-256");
    await expect(startReviewServer({
      databasePath, evidencePacketPath: packetPath, evidencePacketSha256: packet.integrity.packetSha256,
    })).rejects.toThrow("cannot be mixed");
    await writeFile(packetPath, JSON.stringify({ ...packet, localPath: "/private/input" }));
    await expect(startReviewServer({
      evidencePacketPath: packetPath, evidencePacketSha256: packet.integrity.packetSha256,
    })).rejects.toThrow("Evidence packet is invalid");
  });

  it("searches a pinned verified packet collection without a database or source locations", async () => {
    const { root, candidate } = await fixture();
    const secondCandidate = { ...candidate, id: `${candidate.id}_second` };
    const firstEvidence = await promoteCandidate(candidate, () => new Date("2026-07-12T02:00:00.000Z"));
    const secondEvidence = await promoteCandidate(secondCandidate, () => new Date("2026-07-12T03:00:00.000Z"));
    const packets = [
      await createEvidencePacket(candidate, firstEvidence),
      await createEvidencePacket(secondCandidate, secondEvidence),
    ];
    const packetPaths = [join(root, "first.packet.json"), join(root, "second.packet.json")];
    await Promise.all(packets.map((packet, index) => writeFile(packetPaths[index] as string, JSON.stringify(packet), { mode: 0o600 })));
    const indexPath = join(root, "packet-index.json"), receiptPath = join(root, "packet-audit.json");
    const packetIndex = await createEvidencePacketIndex({
      packetPaths, expectedPacketSha256s: packets.map((packet) => packet.integrity.packetSha256), outputPath: indexPath,
    });
    const { receipt } = await auditEvidencePacketCollection({
      indexPath, expectedIndexSha256: packetIndex.integrity.indexSha256, packetPaths, outputPath: receiptPath,
    });
    const server = await startReviewServer({
      evidencePacketPaths: packetPaths,
      evidencePacketIndexPath: indexPath,
      evidencePacketIndexSha256: packetIndex.integrity.indexSha256,
      evidencePacketAuditReceiptPath: receiptPath,
      evidencePacketAuditReceiptSha256: receipt.integrity.auditSha256,
    });
    servers.push(server);
    const bootstrap = await (await fetch(`${server.url}/api/review-bootstrap`)).json() as {
      review: { totals: Record<string, number>; items: Array<{ id: string; source: string }> };
    };
    expect(bootstrap.review.totals).toEqual({ all: 2, candidate: 0, rejected: 0, verified: 2 });
    expect(bootstrap.review.items.map((item) => item.id)).toEqual([candidate.id, secondCandidate.id]);
    expect(bootstrap.review.items.every((item) => item.source === "持ち運び用の検証済み記録")).toBe(true);
    const detail = await (await fetch(`${server.url}/api/review/${encodeURIComponent(secondCandidate.id)}`)).json() as {
      provenance: { packetSha256: string }; evidence: { id: string };
    };
    expect(detail).toMatchObject({
      provenance: { packetSha256: packets[1]?.integrity.packetSha256 }, evidence: { id: secondEvidence.id },
    });
    const app = await (await fetch(`${server.url}/app.js`)).text();
    expect(app).toContain("件の検証済み記録を、元の保存場所に触れず検索・確認する。");
    expect(JSON.stringify({ bootstrap, detail })).not.toContain(root);
    expect(JSON.stringify({ bootstrap, detail })).not.toContain("file://");

    const bundlePath = join(root, "packet-collection.bundle.json");
    const bundle = await createEvidencePacketCollectionBundle({
      indexPath, expectedIndexSha256: packetIndex.integrity.indexSha256,
      auditReceiptPath: receiptPath, expectedAuditSha256: receipt.integrity.auditSha256,
      packetPaths, outputPath: bundlePath,
    });
    const bundleServer = await startReviewServer({
      evidencePacketBundlePath: bundlePath, evidencePacketBundleSha256: bundle.integrity.bundleSha256,
    });
    servers.push(bundleServer);
    const bundleBootstrap = await (await fetch(`${bundleServer.url}/api/review-bootstrap`)).json() as {
      review: { totals: Record<string, number>; items: Array<{ id: string }> };
    };
    expect(bundleBootstrap.review).toEqual(bootstrap.review);
    const bundleDetail = await (await fetch(`${bundleServer.url}/api/review/${encodeURIComponent(secondCandidate.id)}`)).json() as {
      provenance: { packetSha256: string }; evidence: { id: string };
    };
    expect(bundleDetail).toEqual(detail);
    expect(JSON.stringify({ bundleBootstrap, bundleDetail })).not.toContain(root);

    const coherentHistory = await transitionHistoryFixture(root, {
      latestBundleSha256: bundle.integrity.bundleSha256,
      prefix: "coherent-transition-history",
    });
    const coherentServer = await startReviewServer({
      evidencePacketBundlePath: bundlePath,
      evidencePacketBundleSha256: bundle.integrity.bundleSha256,
      packetTransitionHistoryIndexPath: coherentHistory.indexPath,
      packetTransitionHistoryIndexSha256: coherentHistory.index.integrity.indexSha256,
      packetTransitionHistoryAuditReceiptPath: coherentHistory.auditPath,
      packetTransitionHistoryAuditReceiptSha256: coherentHistory.audit.integrity.auditSha256,
    });
    servers.push(coherentServer);
    const coherentBootstrap = await (await fetch(`${coherentServer.url}/api/review-bootstrap`)).json() as {
      transitionHistory: unknown; bundleHistoryReadiness: Record<string, unknown>;
    };
    expect(coherentBootstrap.transitionHistory).toBeNull();
    expect(coherentBootstrap.bundleHistoryReadiness).toEqual({
      version: 1,
      kind: "EvidenceForgeReviewBundleHistoryReadiness",
      outcome: "verified",
      packetCount: 2,
      transitionCount: 1,
      latestBundleSha256: bundle.integrity.bundleSha256,
      historyCollectionReaudited: false,
      timestampAttested: false,
    });
    expect((await fetch(`${coherentServer.url}/api/packet-transition-history`)).status).toBe(404);
    expect((await fetch(`${coherentServer.url}/api/bundle-history-readiness`)).status).toBe(200);
    expect(await (await fetch(`${coherentServer.url}/app.js`)).text()).toContain("最新地点と一致");

    const mismatchedHistory = await transitionHistoryFixture(root, { prefix: "mismatched-transition-history" });
    await expect(startReviewServer({
      evidencePacketBundlePath: bundlePath,
      evidencePacketBundleSha256: bundle.integrity.bundleSha256,
      packetTransitionHistoryIndexPath: mismatchedHistory.indexPath,
      packetTransitionHistoryIndexSha256: mismatchedHistory.index.integrity.indexSha256,
      packetTransitionHistoryAuditReceiptPath: mismatchedHistory.auditPath,
      packetTransitionHistoryAuditReceiptSha256: mismatchedHistory.audit.integrity.auditSha256,
    })).rejects.toThrow("does not match the latest transition history endpoint");

    await expect(startReviewServer({
      evidencePacketPaths: packetPaths, evidencePacketIndexPath: indexPath,
    })).rejects.toThrow("requires an index");
    await expect(startReviewServer({
      databasePath: join(root, "workspace.sqlite"), evidencePacketPaths: packetPaths,
      evidencePacketIndexPath: indexPath, evidencePacketIndexSha256: packetIndex.integrity.indexSha256,
      evidencePacketAuditReceiptPath: receiptPath, evidencePacketAuditReceiptSha256: receipt.integrity.auditSha256,
    })).rejects.toThrow("cannot be mixed");
    await expect(startReviewServer({
      evidencePacketPaths: [...packetPaths].reverse(),
      evidencePacketIndexPath: indexPath, evidencePacketIndexSha256: packetIndex.integrity.indexSha256,
      evidencePacketAuditReceiptPath: receiptPath, evidencePacketAuditReceiptSha256: receipt.integrity.auditSha256,
    })).rejects.toMatchObject({ code: "PACKET_COLLECTION_REORDERED" });
    await expect(startReviewServer({ evidencePacketBundlePath: bundlePath }))
      .rejects.toThrow("requires a bundle and expected SHA-256");
    await expect(startReviewServer({
      databasePath: join(root, "bundle.sqlite"),
      evidencePacketBundlePath: bundlePath, evidencePacketBundleSha256: bundle.integrity.bundleSha256,
    })).rejects.toThrow("cannot be mixed");
  });

  it("shows bounded web provenance without refetching or exposing local paths and fails ambiguous linkage closed", async () => {
    const fixtureValue = await fixture();
    const web = webFixture(fixtureValue.candidate);
    const workspace = new LocalWorkspace(fixtureValue.databasePath);
    workspace.saveWebCapture(web.capture);
    workspace.saveCandidate(web.candidate);
    workspace.close();

    const server = await startReviewServer({ databasePath: fixtureValue.databasePath });
    servers.push(server);
    const summary = await (await fetch(`${server.url}/api/review`)).json() as { items: Array<{ source: string }> };
    expect(summary.items[0]?.source).toBe("https://example.com/final");
    const detailUrl = `${server.url}/api/review/${encodeURIComponent(web.candidate.id)}`;
    const detail = await (await fetch(detailUrl)).json() as { provenance: Record<string, unknown> };
    expect(detail.provenance).toMatchObject({
      kind: "web", integrity: "verified", requestedUrl: "https://example.com/start",
      canonicalUrl: "https://example.com/final", redirectCount: 1, status: 200,
      assurance: "integrity-checked-retained-snapshot",
      representation: { contentType: "text/html; charset=utf-8", contentLanguage: "ja", contentEncoding: "identity" },
    });
    expect(detail).toMatchObject({ citationView: {
      kind: "DerivedCitationView", transformation: "evidence-forge/html-text@1", sourceSha256: web.capture.snapshot.sha256,
    } });
    expect(JSON.stringify(detail)).not.toContain(fixtureValue.root);
    expect(JSON.stringify(detail)).not.toContain("hidden");

    const duplicateWorkspace = new LocalWorkspace(fixtureValue.databasePath);
    duplicateWorkspace.saveWebCapture({ ...web.capture, id: `${web.capture.id}_duplicate` });
    duplicateWorkspace.close();
    const ambiguous = await (await fetch(detailUrl)).json() as { provenance: { integrity: string; message: string } };
    expect(ambiguous.provenance).toEqual({
      kind: "web", integrity: "failed", message: "対応するWeb取得記録を一意に特定できません。",
    });
  });

  it("rejects writes and non-local Host headers", async () => {
    const { databasePath } = await fixture();
    new LocalWorkspace(databasePath).close();
    const server = await startReviewServer({ databasePath });
    servers.push(server);
    expect((await fetch(`${server.url}/api/review`, { method: "POST" })).status).toBe(405);
    expect(await statusWithHost(server.url, "attacker.example")).toBe(421);
    expect(await statusWithHost(server.url, "127.0.0.1:4173.attacker.example")).toBe(421);
  });

  it("rejects invalid ports before opening the workspace", async () => {
    await expect(startReviewServer({ databasePath: "/does/not/matter.sqlite", port: Number.NaN }))
      .rejects.toThrow("port must be an integer");
    await expect(startReviewServer({ databasePath: "/does/not/matter.sqlite", port: 65_536 }))
      .rejects.toThrow("port must be an integer");
  });

  it("never silently downgrades incomplete signature configuration", async () => {
    await expect(startReviewServer({ databasePath: "/does/not/matter.sqlite", trustedPublicKeyPaths: ["public.pem"] }))
      .rejects.toThrow("requires a report, signatures, and trusted public keys");
    await expect(startReviewServer({ databasePath: "/does/not/matter.sqlite", revokedKeyIds: ["not-a-key-id"] }))
      .rejects.toThrow("requires a report, signatures, and trusted public keys");
  });

  it("exposes bounded quorum metadata without local key or signature paths", async () => {
    const { root, databasePath } = await fixture();
    const trustValidUntil = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const value = {
      version: 1, recordedAt: "2026-07-13T12:00:00.000Z", outcome: "verified", eventCount: 4,
      trustedHeadSha256: "a".repeat(64), candidateKind: "EvidenceCandidate", evidenceKind: "VerifiedEvidence",
      candidateLinked: true, revisions: {
        evidenceForge: { commit: "b".repeat(40), clean: true },
        agentBlackBox: { commit: "c".repeat(40), clean: true },
        solLedger: { commit: "d".repeat(40), clean: true },
      },
    } as const;
    const reportPath = join(root, "report.json");
    await writeFile(reportPath, JSON.stringify({
      ...value, integrity: { algorithm: "sha256-jcs", reportSha256: canonicalJsonSha256(value) },
    }));
    const keyPaths: Array<{ privatePath: string; publicPath: string; signaturePath: string }> = [];
    for (const index of [0, 1]) {
      const pair = generateKeyPairSync("ed25519");
      const privatePath = join(root, `private-${String(index)}.pem`);
      const publicPath = join(root, `public-${String(index)}.pem`);
      const signaturePath = join(root, `signature-${String(index)}.json`);
      await writeFile(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      await writeFile(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }));
      await signStackReport(reportPath, privatePath, signaturePath);
      keyPaths.push({ privatePath, publicPath, signaturePath });
    }
    new LocalWorkspace(databasePath).close();
    const server = await startReviewServer({
      databasePath,
      stackReportPath: reportPath,
      stackSignaturePaths: keyPaths.map((key) => key.signaturePath),
      trustedPublicKeyPaths: keyPaths.map((key) => key.publicPath),
      signatureThreshold: 2,
      trustValidUntil,
    });
    servers.push(server);
    const body = await (await fetch(`${server.url}/api/stack-history`)).text();
    const history = JSON.parse(body) as { reports: Array<{ signature?: { algorithm: string; threshold: number; verifiedKeyIds: string[] } }> };
    expect(history.reports[0]?.signature).toMatchObject({ algorithm: "ed25519", threshold: 2 });
    expect(history.reports[0]?.signature?.verifiedKeyIds).toHaveLength(2);
    expect(body).not.toContain(root);
    expect(body).not.toContain("BEGIN PUBLIC KEY");

    const bundlePath = join(root, "portable-review.bundle.json");
    const bundle = await createStackReviewBundle(
      reportPath,
      keyPaths.map((key) => key.signaturePath),
      keyPaths.map((key) => key.publicPath),
      bundlePath,
    );
    await expect(startReviewServer({ databasePath, stackBundlePath: bundlePath }))
      .rejects.toThrow("explicitly trusted key IDs");
    await expect(startReviewServer({
      databasePath, stackBundlePath: bundlePath, stackReportPath: reportPath,
      trustedKeyIds: bundle.publicKeys.map((key) => key.keyId),
    })).rejects.toThrow("cannot be mixed");
    const bundleServer = await startReviewServer({
      databasePath,
      stackBundlePath: bundlePath,
      trustedKeyIds: bundle.publicKeys.map((key) => key.keyId),
      signatureThreshold: 2,
      trustValidUntil,
    });
    servers.push(bundleServer);
    const bundleBody = await (await fetch(`${bundleServer.url}/api/stack-history`)).text();
    expect(bundleBody).not.toContain(root);
    expect(JSON.parse(bundleBody) as unknown).toEqual(JSON.parse(body) as unknown);

    const manifestPath = join(root, "workspace-trust.json");
    const manifest = await createManualTrustManifest({
      publicKeyPaths: keyPaths.map((key) => key.publicPath), threshold: 2, outputPath: manifestPath,
    });
    const manifestServer = await startReviewServer({
      databasePath, stackBundlePath: bundlePath, trustManifestPath: manifestPath,
      trustManifestSha256: manifest.integrity.manifestSha256,
    });
    servers.push(manifestServer);
    expect((await fetch(`${manifestServer.url}/api/stack-history`)).status).toBe(200);
    await expect(startReviewServer({
      databasePath, stackBundlePath: bundlePath, trustManifestPath: manifestPath,
      trustManifestSha256: manifest.integrity.manifestSha256, signatureThreshold: 2,
    })).rejects.toThrow("cannot be mixed");
  });

  it("serves a validated stack report without accepting arbitrary JSON", async () => {
    const { root, databasePath } = await fixture();
    const reportPath = join(root, "report.json");
    await writeFile(reportPath, JSON.stringify({
      version: 1, outcome: "verified", eventCount: 4, trustedHeadSha256: "a".repeat(64),
      candidateKind: "EvidenceCandidate", evidenceKind: "VerifiedEvidence", candidateLinked: true,
      revisions: {
        evidenceForge: { commit: "b".repeat(40), clean: true },
        agentBlackBox: { commit: "c".repeat(40), clean: true },
        solLedger: { commit: "d".repeat(40), clean: true },
      },
    }));
    new LocalWorkspace(databasePath).close();
    const server = await startReviewServer({ databasePath, stackReportPath: reportPath });
    servers.push(server);
    const response = await fetch(`${server.url}/api/stack-report`);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ outcome: "verified", eventCount: 4 });
  });

  it("accepts planned key rotation and rejects an unexpected signer replacement", async () => {
    const { root, databasePath } = await fixture();
    const value = {
      version: 1, recordedAt: "2026-07-13T02:00:00.000Z", outcome: "verified", eventCount: 4,
      trustedHeadSha256: "e".repeat(64), candidateKind: "EvidenceCandidate", evidenceKind: "VerifiedEvidence",
      candidateLinked: true, revisions: {
        evidenceForge: { commit: "b".repeat(40), clean: true },
        agentBlackBox: { commit: "c".repeat(40), clean: true },
        solLedger: { commit: "d".repeat(40), clean: true },
      },
    } as const;
    const reportPath = join(root, "rotation-report.json");
    await writeFile(reportPath, JSON.stringify({ ...value, integrity: { algorithm: "sha256-jcs", reportSha256: canonicalJsonSha256(value) } }));
    const rotationKeys: Array<{ privatePath: string; publicPath: string; signaturePath: string }> = [];
    for (const name of ["a", "b", "c"]) {
      const pair = generateKeyPairSync("ed25519");
      const privatePath = join(root, `${name}-private.pem`), publicPath = join(root, `${name}-public.pem`);
      const signaturePath = join(root, `${name}-report.sig.json`);
      await writeFile(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      await writeFile(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }));
      await signStackReport(reportPath, privatePath, signaturePath);
      rotationKeys.push({ privatePath, publicPath, signaturePath });
    }
    const [a, b, c] = rotationKeys;
    if (!a || !b || !c) throw new Error("Rotation fixture is incomplete");
    const historyOnePath = join(root, "trust-history-1.json");
    const historyOne = await appendTrustRotation({
      effectiveAt: "2026-07-13T00:00:00.000Z",
      trustedPublicKeyPaths: [a.publicPath, b.publicPath], threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath, b.privatePath], outputPath: historyOnePath,
    });
    const anchors = historyOne.entries[0]?.policy.keyIds;
    if (!anchors) throw new Error("Rotation fixture has no anchors");
    const historyTwoPath = join(root, "trust-history-2.json");
    const historyTwo = await appendTrustRotation({
      historyPath: historyOnePath, anchorKeyIds: anchors, anchorThreshold: 2,
      expectedHistorySha256: historyOne.integrity.historySha256, effectiveAt: "2026-07-13T01:00:00.000Z",
      trustedPublicKeyPaths: [b.publicPath, c.publicPath], threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath, b.privatePath], outputPath: historyTwoPath,
    });
    const plannedBundlePath = join(root, "planned.bundle.json");
    await createStackReviewBundle(reportPath, [b.signaturePath, c.signaturePath], [b.publicPath, c.publicPath], plannedBundlePath);
    new LocalWorkspace(databasePath).close();
    const server = await startReviewServer({
      databasePath, stackBundlePath: plannedBundlePath,
      trustHistoryPath: historyTwoPath, trustAnchorKeyIds: anchors, trustAnchorThreshold: 2,
      trustHistorySha256: historyTwo.integrity.historySha256,
    });
    servers.push(server);
    const historyResponse = await (await fetch(`${server.url}/api/stack-history`)).json() as {
      reports: Array<{ trustRotation?: { completedRotations: number; scheduledCount: number; latestAddedKeyCount: number; latestRemovedKeyCount: number } }>;
    };
    expect(historyResponse.reports[0]?.trustRotation).toMatchObject({
      completedRotations: 1, scheduledCount: 0, latestAddedKeyCount: 1, latestRemovedKeyCount: 1,
    });
    const unexpectedBundlePath = join(root, "unexpected.bundle.json");
    await createStackReviewBundle(reportPath, [a.signaturePath, b.signaturePath], [a.publicPath, b.publicPath], unexpectedBundlePath);
    await expect(startReviewServer({
      databasePath, stackBundlePath: unexpectedBundlePath,
      trustHistoryPath: historyTwoPath, trustAnchorKeyIds: anchors, trustAnchorThreshold: 2,
      trustHistorySha256: historyTwo.integrity.historySha256,
    })).rejects.toThrow("does not satisfy the active trust-rotation policy");
  });

  it("orders bounded stack history newest-first and rejects duplicate heads", async () => {
    const { root, databasePath } = await fixture();
    const report = (head: string, recordedAt: string) => ({
      version: 1, outcome: "verified", eventCount: 4, trustedHeadSha256: head.repeat(64), recordedAt,
      candidateKind: "EvidenceCandidate", evidenceKind: "VerifiedEvidence", candidateLinked: true,
      revisions: {
        evidenceForge: { commit: "b".repeat(40), clean: true },
        agentBlackBox: { commit: "c".repeat(40), clean: true },
        solLedger: { commit: "d".repeat(40), clean: true },
      },
    });
    const older = join(root, "older.json"); const newer = join(root, "newer.json");
    await writeFile(older, JSON.stringify(report("a", "2026-07-12T00:00:00.000Z")));
    await writeFile(newer, JSON.stringify(report("e", "2026-07-13T00:00:00.000Z")));
    new LocalWorkspace(databasePath).close();
    const server = await startReviewServer({ databasePath, stackReportPaths: [older, newer] });
    servers.push(server);
    const history = await (await fetch(`${server.url}/api/stack-history`)).json() as { reports: Array<{ trustedHeadSha256: string }> };
    expect(history.reports.map((item) => item.trustedHeadSha256[0])).toEqual(["e", "a"]);
    expect(await (await fetch(`${server.url}/app.js`)).text()).toContain("前回との差分");
    await expect(startReviewServer({ databasePath, stackReportPaths: [older, older] }))
      .rejects.toThrow("duplicate trusted head");
  });
});

async function statusWithHost(base: string, host: string): Promise<number> {
  return await new Promise((resolve, reject) => {
    const req = request(`${base}/api/review`, { headers: { host } }, (response) => {
      response.resume(); response.on("end", () => { resolve(response.statusCode ?? 0); });
    });
    req.on("error", reject); req.end();
  });
}
