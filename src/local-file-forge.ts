import { lstat, mkdir, rm, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { diagnosticError } from "./diagnostics.js";
import { captureLocalCitation } from "./forge.js";
import { runLocalEvidencePipeline } from "./local-evidence-pipeline.js";
import { writePrivateFileExclusive } from "./private-file.js";

const USAGE = "Usage: evidence-forge forge-local --source FILE --exact TEXT --available-at ISO --directory NEW_DIR --promote-immediately [--error-format json]";

const ARTIFACTS = {
  candidate: "candidate.json",
  evidence: "verified-evidence.json",
  packet: "evidence-packet.json",
  verification: "packet-verification.json",
  result: "forge-result.json",
} as const;

export interface LocalFileForgeOptions {
  readonly sourcePath: string;
  readonly exact: string;
  readonly availableAt: string;
  readonly directory: string;
  readonly promotionPreauthorized: true;
}

export interface LocalFileForgeResult {
  readonly version: 1;
  readonly kind: "EvidenceForgeLocalFileResult";
  readonly outcome: "verified";
  readonly stages: readonly [
    { readonly name: "capture"; readonly status: "observation" },
    { readonly name: "promote"; readonly status: "evidence" },
    { readonly name: "packet"; readonly status: "portable" },
    { readonly name: "verify"; readonly status: "verified" },
  ];
  readonly artifacts: typeof ARTIFACTS;
  readonly candidateId: string;
  readonly evidenceId: string;
  readonly packetSha256: string;
  readonly assurance: {
    readonly localOnly: true;
    readonly promotionPreauthorized: true;
    readonly existingFilesOverwritten: false;
    readonly rawSourcePrinted: false;
    readonly timestampAttested: false;
  };
}

export function parseLocalFileForgeArguments(arguments_: readonly string[]): LocalFileForgeOptions {
  if (arguments_[0] !== "forge-local") throw new Error(USAGE);
  const values = new Map<string, string>();
  let promotionPreauthorized = false;
  let errorFormatSeen = false;
  for (let index = 1; index < arguments_.length; index += 1) {
    const name = arguments_[index];
    if (name === "--promote-immediately" && !promotionPreauthorized) {
      promotionPreauthorized = true;
      continue;
    }
    const value = arguments_[index + 1];
    if (name === "--error-format" && !errorFormatSeen && value === "json") {
      errorFormatSeen = true;
      index += 1;
      continue;
    }
    if (!["--source", "--exact", "--available-at", "--directory"].includes(name ?? "") ||
        values.has(name ?? "") || !value || (name !== "--exact" && value.startsWith("--"))) {
      throw new Error(USAGE);
    }
    values.set(name as string, value);
    index += 1;
  }
  if (!promotionPreauthorized) {
    throw diagnosticError(
      "PROMOTION_PREAUTHORIZATION_REQUIRED",
      "--promote-immediately is required; use capture and promote separately to inspect the Candidate first",
    );
  }
  if (values.size !== 4) throw new Error(USAGE);
  return {
    sourcePath: resolve(required(values, "--source")),
    exact: required(values, "--exact"),
    availableAt: required(values, "--available-at"),
    directory: resolve(required(values, "--directory")),
    promotionPreauthorized: true,
  };
}

/**
 * Runs the complete local-file path in one process. Requiring an explicit
 * promotion confirmation keeps the candidate-to-evidence transition visible.
 */
export async function forgeLocalFile(options: LocalFileForgeOptions): Promise<LocalFileForgeResult> {
  await assertSafeOutputParent(options.directory);
  try {
    await mkdir(options.directory, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error("Forge output directory already exists; choose a new --directory");
    }
    throw error;
  }
  const createdDirectory = await lstat(options.directory);

  try {
    const workspace = join(options.directory, "workspace");
    await mkdir(workspace, { mode: 0o700 });
    const candidate = await captureLocalCitation({
      workspace,
      sourcePath: options.sourcePath,
      exact: options.exact,
      availableAt: options.availableAt,
    });
    await writeJson(join(options.directory, ARTIFACTS.candidate), candidate);

    const { evidence, packet, verification } = await runLocalEvidencePipeline(candidate);
    await writeJson(join(options.directory, ARTIFACTS.evidence), evidence);
    await writeJson(join(options.directory, ARTIFACTS.packet), packet);
    await writeJson(join(options.directory, ARTIFACTS.verification), verification);

    const result: LocalFileForgeResult = {
      version: 1,
      kind: "EvidenceForgeLocalFileResult",
      outcome: "verified",
      stages: [
        { name: "capture", status: "observation" },
        { name: "promote", status: "evidence" },
        { name: "packet", status: "portable" },
        { name: "verify", status: "verified" },
      ],
      artifacts: ARTIFACTS,
      candidateId: candidate.id,
      evidenceId: evidence.id,
      packetSha256: packet.integrity.packetSha256,
      assurance: {
        localOnly: true,
        promotionPreauthorized: true,
        existingFilesOverwritten: false,
        rawSourcePrinted: false,
        timestampAttested: false,
      },
    };
    await writeJson(join(options.directory, ARTIFACTS.result), result);
    return result;
  } catch (error) {
    await removeCreatedDirectory(options.directory, createdDirectory);
    throw error;
  }
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writePrivateFileExclusive(path, `${JSON.stringify(value, null, 2)}\n`);
}

function required(values: ReadonlyMap<string, string>, name: string): string {
  const value = values.get(name);
  if (value === undefined) throw new Error(USAGE);
  return value;
}

async function assertSafeOutputParent(directory: string): Promise<void> {
  const parent = await stat(dirname(directory));
  if (!parent.isDirectory()) throw new Error("Forge output parent must be a directory");
  if (process.platform !== "win32" && (parent.mode & 0o022) !== 0 && (parent.mode & 0o1000) === 0) {
    throw new Error("Forge output parent must not be group/world-writable unless it has the sticky bit");
  }
}

export async function removeCreatedDirectory(directory: string, created: Awaited<ReturnType<typeof lstat>>): Promise<void> {
  let current;
  try {
    current = await lstat(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!current.isDirectory() || current.dev !== created.dev || current.ino !== created.ino) {
    throw new Error("Forge cleanup refused because the output directory identity changed");
  }
  await rm(directory, { recursive: true, force: true });
}
