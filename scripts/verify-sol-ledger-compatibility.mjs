import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  canonicalJsonSha256,
  SOL_LEDGER_PROTOCOL_COMMIT,
  toSolLedgerBundle,
} from "../dist/src/sol-ledger.js";

const protocolArgument = process.argv.slice(2).find((argument) => argument !== "--");
const protocolDir = resolve(protocolArgument ?? "work/sol-ledger-protocol-v0.1.0");
const actualCommit = execFileSync("git", ["-C", protocolDir, "rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
if (actualCommit !== SOL_LEDGER_PROTOCOL_COMMIT) {
  throw new Error(`Expected Sol Ledger ${SOL_LEDGER_PROTOCOL_COMMIT}, got ${actualCommit}`);
}

const ajv = new Ajv2020({ allErrors: true });
addFormats(ajv);
for (const name of ["security-policy", "event-envelope", "artifact-ref", "provenance-edge"]) {
  const schema = JSON.parse(readFileSync(resolve(protocolDir, "schemas", `${name}.schema.json`), "utf8"));
  ajv.addSchema(schema);
}

const evidence = {
  kind: "VerifiedEvidence",
  id: "evidence_compatibility",
  candidateId: "candidate_compatibility",
  snapshot: {
    mediaType: "text/plain; charset=utf-8",
    sha256: "a".repeat(64),
    byteLength: 42,
    objectPath: "/private/source-object",
    sourceUri: "file:///private/source.txt",
    capturedAt: "2026-07-11T01:00:00.000Z",
    availableAt: "2026-07-11T00:00:00.000Z",
  },
  selector: {
    type: "TextQuoteSelector",
    exact: "The verified fact is 42.",
    prefix: "Alpha. ",
    suffix: " Omega.",
  },
  observedAt: "2026-07-11T01:00:00.000Z",
  verifiedAt: "2026-07-11T02:00:00.000Z",
};
const bundle = toSolLedgerBundle(evidence);
const records = [
  ["artifact-ref", bundle.artifact],
  ["event-envelope", bundle.event],
  ["provenance-edge", bundle.provenance],
];

for (const [name, record] of records) {
  const validate = ajv.getSchema(`https://sol-ledger.dev/schema/${name}/0.1.0`);
  if (!validate(record)) throw new Error(`${name} incompatible: ${JSON.stringify(validate.errors)}`);
}

const htmlBundle = toSolLedgerBundle({
  ...evidence,
  snapshot: { ...evidence.snapshot, mediaType: "text/html; charset=utf-8" },
  citationView: {
    kind: "DerivedCitationView", transformation: "evidence-forge/html-text@1",
    sourceSha256: evidence.snapshot.sha256, mediaType: "text/plain; charset=utf-8",
    sha256: "b".repeat(64), byteLength: 31,
  },
});
const validateHtmlEvent = ajv.getSchema("https://sol-ledger.dev/schema/event-envelope/0.1.0");
if (!validateHtmlEvent(htmlBundle.event)) {
  throw new Error(`HTML citation event incompatible: ${JSON.stringify(validateHtmlEvent.errors)}`);
}

const temporaryDirectory = mkdtempSync(join(tmpdir(), "evidence-forge-sol-ledger-"));
try {
  const eventPath = join(temporaryDirectory, "event-chain.jsonl");
  writeFileSync(eventPath, `${JSON.stringify(bundle.event)}\n`);
  const trustedHead = canonicalJsonSha256(bundle.event);
  execFileSync(
    "cargo",
    [
      "run", "--quiet", "-p", "sol-ledger-cli", "--", "verify-chain", eventPath,
      "--expected-head-sha256", trustedHead,
    ],
    { cwd: protocolDir, encoding: "utf8" },
  );
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}

console.log(`Compatible with Sol Ledger Protocol ${actualCommit}: ${records.map(([name]) => name).join(", ")}; Rust/JCS chain verified`);
