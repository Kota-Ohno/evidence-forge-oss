import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { EvidenceCandidate } from "./domain.js";
import { captureLocalCitation } from "./forge.js";
import { runLocalEvidencePipeline } from "./local-evidence-pipeline.js";
import { writePrivateFileExclusive } from "./private-file.js";

const SOURCE_TEXT = [
  "Evidence Forge quickstart begins with a local observation.",
  "Only promotion turns this quoted observation into verified evidence.",
  "The portable packet can then be checked offline.",
  "",
].join("\n");
const EXACT = "Only promotion turns this quoted observation into verified evidence.";
const AVAILABLE_AT = "2024-01-01T00:00:00.000Z";
const CAPTURED_AT = new Date("2024-01-02T00:00:00.000Z");
const VERIFIED_AT = new Date("2024-01-03T00:00:00.000Z");
const CANDIDATE_ID = "candidate_quickstart_local";
const EVIDENCE_ID = "evidence_quickstart_local";

export const DEFAULT_QUICKSTART_DIRECTORY = "evidence-forge-quickstart";
const QUICKSTART_USAGE = "Usage: evidence-forge quickstart [--directory NEW_DIR] [--error-format json]";

const ARTIFACTS = {
  source: "source.txt",
  candidate: "candidate.json",
  evidence: "verified-evidence.json",
  packet: "evidence-packet.json",
  verification: "packet-verification.json",
  result: "quickstart-result.json",
} as const;

export interface QuickstartResult {
  readonly version: 1;
  readonly kind: "EvidenceForgeQuickstartResult";
  readonly outcome: "verified";
  readonly stages: readonly [
    { readonly name: "capture"; readonly outputKind: "EvidenceCandidate"; readonly status: "observation" },
    { readonly name: "promote"; readonly outputKind: "VerifiedEvidence"; readonly status: "evidence" },
    { readonly name: "packet"; readonly outputKind: "PortableEvidencePacket" },
    { readonly name: "verify"; readonly outcome: "verified" },
  ];
  readonly artifacts: typeof ARTIFACTS;
  readonly candidateId: typeof CANDIDATE_ID;
  readonly evidenceId: typeof EVIDENCE_ID;
  readonly packetSha256: string;
  readonly assurance: {
    readonly localOnly: true;
    readonly existingFilesOverwritten: false;
    readonly rawSourcePrinted: false;
    readonly timestampAttested: false;
  };
}

export function parseQuickstartArguments(arguments_: readonly string[]): string {
  if (arguments_[0] !== "quickstart") throw new Error(QUICKSTART_USAGE);
  let directory: string | undefined;
  let errorFormatSeen = false;
  for (let index = 1; index < arguments_.length; index += 1) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (name === "--directory" && directory === undefined && value && !value.startsWith("--")) {
      directory = resolve(value);
      index += 1;
      continue;
    }
    if (name === "--error-format" && !errorFormatSeen && value === "json") {
      errorFormatSeen = true;
      index += 1;
      continue;
    }
    throw new Error(QUICKSTART_USAGE);
  }
  return directory ?? resolve(DEFAULT_QUICKSTART_DIRECTORY);
}

/**
 * Creates a closed local tutorial run in a directory that must not exist yet.
 * The candidate is persisted before—and separately from—the gated evidence.
 */
export async function runQuickstart(directory: string): Promise<QuickstartResult> {
  try {
    await mkdir(directory, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error("Quickstart output directory already exists; choose a new --directory");
    }
    throw error;
  }

  const sourcePath = join(directory, ARTIFACTS.source);
  const workspacePath = join(directory, "workspace");
  await mkdir(workspacePath, { mode: 0o700 });
  await writePrivateFileExclusive(sourcePath, SOURCE_TEXT);

  const captured = await captureLocalCitation({
    workspace: workspacePath,
    sourcePath,
    exact: EXACT,
    availableAt: AVAILABLE_AT,
    now: () => new Date(CAPTURED_AT),
  });
  const candidate: EvidenceCandidate = { ...captured, id: CANDIDATE_ID };
  await writeJson(join(directory, ARTIFACTS.candidate), candidate);

  // This is the only transition that creates evidence. Packet creation also
  // independently replays this gate before exporting the portable artifact.
  const { evidence, packet, verification } = await runLocalEvidencePipeline(candidate, {
    now: () => new Date(VERIFIED_AT), evidenceId: EVIDENCE_ID,
  });
  await writeJson(join(directory, ARTIFACTS.evidence), evidence);
  await writeJson(join(directory, ARTIFACTS.packet), packet);
  await writeJson(join(directory, ARTIFACTS.verification), verification);

  const result: QuickstartResult = {
    version: 1,
    kind: "EvidenceForgeQuickstartResult",
    outcome: "verified",
    stages: [
      { name: "capture", outputKind: "EvidenceCandidate", status: "observation" },
      { name: "promote", outputKind: "VerifiedEvidence", status: "evidence" },
      { name: "packet", outputKind: "PortableEvidencePacket" },
      { name: "verify", outcome: "verified" },
    ],
    artifacts: ARTIFACTS,
    candidateId: CANDIDATE_ID,
    evidenceId: EVIDENCE_ID,
    packetSha256: packet.integrity.packetSha256,
    assurance: {
      localOnly: true,
      existingFilesOverwritten: false,
      rawSourcePrinted: false,
      timestampAttested: false,
    },
  };
  await writeJson(join(directory, ARTIFACTS.result), result);
  return result;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writePrivateFileExclusive(path, `${JSON.stringify(value, null, 2)}\n`);
}
