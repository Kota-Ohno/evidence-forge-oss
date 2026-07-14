import assert from "node:assert/strict";
import test from "node:test";
import { parsePackedUpgradeWorkspaceArguments } from "./verify-packed-upgrade-workspace.mjs";

test("packed upgrade workspace acceptance requires every external anchor", () => {
  const sha = "a".repeat(64), key = "b".repeat(64);
  const arguments_ = [
    "--release-pack", "./release.json", "--release-pack-sha256", sha, "--release-key-id", key,
    "--release-index", "./release-index.json", "--release-index-sha256", sha,
    "--archive-audit-receipt", "./archive-audit.json", "--archive-audit-receipt-sha256", sha,
    "--upgrade-history-index", "./history.json", "--upgrade-history-index-sha256", sha,
    "--upgrade-history-audit-receipt", "./audit.json", "--upgrade-history-audit-receipt-sha256", sha,
    "--output", "./result",
  ];
  const parsed = parsePackedUpgradeWorkspaceArguments(arguments_);
  assert.match(parsed.releasePack, /release\.json$/u);
  assert.match(parsed.releaseIndex, /release-index\.json$/u);
  assert.match(parsed.archiveAuditReceipt, /archive-audit\.json$/u);
  assert.match(parsed.upgradeHistoryIndex, /history\.json$/u);
  assert.match(parsed.upgradeHistoryAuditReceipt, /audit\.json$/u);
  assert.match(parsed.output, /result$/u);
  assert.deepEqual(parsePackedUpgradeWorkspaceArguments(["--help"]), { help: true });
  assert.throws(() => parsePackedUpgradeWorkspaceArguments(arguments_.slice(0, -2)), /Missing --output/u);
  assert.throws(() => parsePackedUpgradeWorkspaceArguments(arguments_.map((value) => value === sha ? "invalid" : value)), /must be SHA-256/u);
  assert.throws(() => parsePackedUpgradeWorkspaceArguments([...arguments_, "--output", "./duplicate"]), /Usage:/u);
});
