import assert from "node:assert/strict";
import test from "node:test";
import { assertPrivateTrace, parseArguments } from "./dogfood-stack.mjs";
import { parseArguments as parseReviewArguments } from "./dogfood-review.mjs";
import { assertPackageEntries } from "./verify-package-install.mjs";
import { parsePackedAcceptanceArguments } from "./verify-packed-operator-acceptance.mjs";
import { FAILURE_MATRIX, verifyFailureMatrix } from "./verify-failure-matrix.mjs";

test("parseArguments accepts only the three explicit paths", () => {
  const parsed = parseArguments([
    "--agent-black-box", "./agent", "--sol-ledger", "./protocol", "--output", "./result",
  ]);
  assert.match(parsed.agentBlackBox, /agent$/u);
  assert.match(parsed.solLedger, /protocol$/u);
  assert.match(parsed.output, /result$/u);
  assert.deepEqual(parseArguments([
    "--", "--agent-black-box", "./agent", "--sol-ledger", "./protocol", "--output", "./result",
  ]), parsed);
  assert.deepEqual(parseArguments(["--help"]), { help: true });
  assert.throws(() => parseArguments(["--agent-black-box", "./agent"]), /Missing required option/u);
  assert.throws(() => parseArguments([
    "--agent-black-box", "./agent", "--sol-ledger", "./protocol", "--output", "./result", "--shell", "true",
  ]), /Unsupported or duplicate option/u);
});

test("review dogfood accepts the same shell-free contract and help", () => {
  const parsed = parseReviewArguments([
    "--agent-black-box", "./agent", "--sol-ledger", "./protocol", "--output", "./result",
  ]);
  assert.match(parsed.agentBlackBox, /agent$/u);
  assert.match(parsed.solLedger, /protocol$/u);
  assert.match(parsed.output, /result$/u);
  assert.deepEqual(parseReviewArguments(["--help"]), { help: true });
  assert.throws(() => parseReviewArguments(["--output", "./result"]), /Missing required option/u);
});

test("release package allowlist rejects development-only files", () => {
  const entries = [
    "package/package.json", "package/LICENSE", "package/README.md", "package/docs/OPERATOR.md",
    "package/docs/TRUST-AUDIT.md",
    "package/schemas/capability-compatibility-receipt.schema.json",
    "package/schemas/cli-capabilities.schema.json",
    "package/schemas/cli-error.schema.json",
    "package/schemas/citation-preview.schema.json",
    "package/schemas/citation-view.schema.json",
    "package/schemas/evidence-candidate.schema.json",
    "package/schemas/evidence-packet.schema.json",
    "package/schemas/evidence-packet-index.schema.json",
    "package/schemas/evidence-packet-collection-audit-receipt.schema.json",
    "package/schemas/evidence-packet-collection-verification.schema.json",
    "package/schemas/evidence-packet-collection-bundle.schema.json",
    "package/schemas/evidence-packet-collection-lineage-bundle.schema.json",
    "package/schemas/evidence-packet-collection-lineage-verification.schema.json",
    "package/schemas/evidence-packet-collection-transition-audit-receipt.schema.json",
    "package/schemas/evidence-packet-collection-transition-verification.schema.json",
    "package/schemas/evidence-packet-transition-history-index.schema.json",
    "package/schemas/evidence-packet-transition-history-audit-receipt.schema.json",
    "package/schemas/evidence-packet-transition-history-audit-verification.schema.json",
    "package/schemas/review-evidence-packet.schema.json",
    "package/schemas/verified-evidence.schema.json",
    "package/schemas/upgrade-contract-evidence.schema.json",
    "package/schemas/release-upgrade-binding-receipt.schema.json",
    "package/schemas/upgrade-history-index.schema.json",
    "package/schemas/upgrade-history-audit-receipt.schema.json",
    "package/schemas/packed-workspace-acceptance-receipt.schema.json",
    "package/schemas/workspace-acceptance-verification.schema.json",
    "package/schemas/cross-release-lineage-acceptance-receipt.schema.json",
    "package/schemas/lineage-continuity-verification.schema.json",
    "package/schemas/current-lineage-continuity-preflight.schema.json",
    "package/schemas/offline-installed-self-test.schema.json",
    "package/schemas/packet-head-inspection.schema.json",
    "package/dist/src/workspace-acceptance-receipt-cli.js",
    "package/dist/src/lineage-continuity-receipt-cli.js",
    "package/dist/src/current-lineage-continuity-preflight-cli.js",
    "package/dist/src/offline-self-test-cli.js",
    "package/dist/src/cli.js", "package/dist/src/index.js",
  ];
  assert.doesNotThrow(() => assertPackageEntries(entries));
  assert.throws(() => assertPackageEntries([...entries, "package/src/cli.ts"]), /development-only files/u);
  assert.throws(() => assertPackageEntries(entries.filter((entry) => entry !== "package/LICENSE")), /missing package\/LICENSE/u);
});

test("packed acceptance requires explicit external repositories and output", () => {
  const parsed = parsePackedAcceptanceArguments([
    "--agent-black-box", "./agent", "--sol-ledger", "./ledger", "--output", "./result",
  ]);
  assert.match(parsed.agentBlackBox, /agent$/u);
  assert.match(parsed.solLedger, /ledger$/u);
  assert.match(parsed.output, /result$/u);
  assert.deepEqual(parsePackedAcceptanceArguments(["--help"]), { help: true });
  assert.throws(() => parsePackedAcceptanceArguments(["--output", "./result"]), /Missing required option/u);
});

test("the named v0.3 failure matrix rejects every unsafe fixture", () => {
  const result = verifyFailureMatrix();
  assert.equal(result.total, FAILURE_MATRIX.length);
  assert.equal(result.passed, FAILURE_MATRIX.length);
  assert.ok(result.results.every((fixture) => fixture.outcome === "rejected"));
});

test("assertPrivateTrace rejects retained content and unsafe modes", () => {
  const event = (eventType, mode = "metadata_only", exitCode) => JSON.stringify({
    eventType, security: { contentMode: mode, sensitivity: "private" },
    payload: exitCode === undefined ? {} : { exitCode },
  });
  const safe = [
    event("command.started"), event("command.finished", "metadata_only", 0),
    event("command.started", "hash_only"), event("command.finished", "metadata_only", 0),
  ].join("\n");
  assert.equal(assertPrivateTrace(safe, ["never-store-this"]), 4);
  assert.throws(() => assertPrivateTrace(`${safe}\nnever-store-this`, ["never-store-this"]), /forbidden content/u);
  assert.throws(() => assertPrivateTrace(safe.replace("metadata_only", "raw"), []), /unsupported content mode/u);
  assert.throws(() => assertPrivateTrace(safe.replace('"exitCode":0', '"exitCode":1'), []), /did not finish successfully/u);
  assert.throws(() => assertPrivateTrace(safe.replace('"sensitivity":"private"', '"sensitivity":"public"'), []), /non-private event/u);
  assert.throws(() => assertPrivateTrace(safe.replace("command.started", "tool.started"), []), /complete command lifecycles/u);
  assert.throws(() => assertPrivateTrace(safe.split("\n").slice(0, 3).join("\n"), []), /Expected 4 lifecycle events/u);
  assert.throws(() => assertPrivateTrace("not-json\n" + safe.split("\n").slice(1).join("\n"), []), /Unexpected token/u);
});
