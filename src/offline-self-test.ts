import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCliCapabilities } from "./capabilities.js";
import { createEvidencePacket, verifyEvidencePacket } from "./evidence-packet.js";
import { captureLocalCitation, promoteCandidate } from "./forge.js";

const EXACT = "Evidence Forge offline self-test validates one exact local citation.";

export interface OfflineInstalledSelfTest {
  readonly version: 1;
  readonly kind: "EvidenceForgeOfflineInstalledSelfTest";
  readonly outcome: "verified";
  readonly packageVersion: string;
  readonly captureVerified: true;
  readonly promotionVerified: true;
  readonly packetRoundTripVerified: true;
  readonly capabilitiesVerified: true;
  readonly networkAccessed: false;
  readonly databaseOpened: false;
  readonly listenerOpened: false;
  readonly temporaryBytesRetained: false;
  readonly timestampAttested: false;
}

interface SelfTestHarness {
  readonly rootObserved?: (root: string) => void;
  readonly afterCapture?: () => void;
}

export async function runOfflineInstalledSelfTest(): Promise<OfflineInstalledSelfTest> {
  return runOfflineInstalledSelfTestWithHarness({});
}

export async function runOfflineInstalledSelfTestWithHarness(
  harness: SelfTestHarness,
): Promise<OfflineInstalledSelfTest> {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-self-test-"));
  try {
    await chmod(root, 0o700);
    harness.rootObserved?.(root);
    const sourcePath = join(root, "source.txt");
    await writeFile(sourcePath, `Private temporary fixture. ${EXACT}\n`, { mode: 0o600, flag: "wx" });
    const candidate = await captureLocalCitation({
      workspace: join(root, "workspace"), sourcePath, exact: EXACT,
      availableAt: "2026-01-01T00:00:00.000Z",
      now: () => new Date("2026-01-01T00:00:01.000Z"),
    });
    harness.afterCapture?.();
    const evidence = await promoteCandidate(candidate, () => new Date("2026-01-01T00:00:02.000Z"));
    const packet = await createEvidencePacket(candidate, evidence);
    const packetVerification = await verifyEvidencePacket(packet, packet.integrity.packetSha256);
    if (packetVerification.candidateId !== candidate.id || packetVerification.evidenceId !== evidence.id ||
        packetVerification.sourceSha256 !== candidate.snapshot.sha256) {
      throw new Error("Offline self-test packet verification did not preserve the promoted citation");
    }
    const capabilities = createCliCapabilities();
    if (!capabilities.binaries.includes("evidence-forge-self-test") ||
        !capabilities.schemas.some((schema) => schema.path === "schemas/offline-installed-self-test.schema.json")) {
      throw new Error("Offline self-test is missing from the installed capability registry");
    }
    return {
      version: 1,
      kind: "EvidenceForgeOfflineInstalledSelfTest",
      outcome: "verified",
      packageVersion: capabilities.package.version,
      captureVerified: true,
      promotionVerified: true,
      packetRoundTripVerified: true,
      capabilitiesVerified: true,
      networkAccessed: false,
      databaseOpened: false,
      listenerOpened: false,
      temporaryBytesRetained: false,
      timestampAttested: false,
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
