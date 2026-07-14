import { describe, expect, it } from "vitest";
import type { ReleaseUpgradeBindingReceipt } from "./release-upgrade-binding.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { appendUpgradeHistoryEntry, parseUpgradeHistoryIndex } from "./upgrade-history-index.js";

function binding(previousVersion: string, currentVersion: string, previousPack: string, currentPack: string, marker: string): ReleaseUpgradeBindingReceipt {
  const digest = (value: string) => value.repeat(64);
  const payload = {
    version: 1 as const, kind: "EvidenceForgeReleaseUpgradeBindingReceipt" as const,
    releases: {
      previous: { packageVersion: previousVersion, packSha256: digest(previousPack), packageSha256: digest("a") },
      current: { packageVersion: currentVersion, packSha256: digest(currentPack), packageSha256: digest("b") },
    },
    upgradeEvidence: {
      evidenceSha256: digest(marker), receiptSha256: digest("c"),
      previousManifestSha256: digest("d"), currentManifestSha256: digest("e"),
    },
    binding: { manifestsReproduced: true as const, lifecycleScripts: "disabled" as const },
    assurance: { timestamp: "not-attested" as const, packageCodeExecution: "capabilities-binary" as const },
  };
  return { ...payload, integrity: { algorithm: "sha256-jcs", bindingSha256: canonicalJsonSha256(payload) } };
}

describe("upgrade history index", () => {
  it("hash-chains contiguous bindings by shared release pack head", () => {
    const first = appendUpgradeHistoryEntry(undefined, binding("2.0.0", "2.1.0", "1", "2", "3"));
    const second = appendUpgradeHistoryEntry(first, binding("2.1.0", "2.2.0", "2", "4", "5"));
    expect(parseUpgradeHistoryIndex(second)).toEqual(second);
    expect(second.entries).toHaveLength(2);
    expect(second.entries[1]?.previousEntrySha256).toBe(second.entries[0]?.entrySha256);
  });

  it("rejects gaps, duplicate bindings, and index mutation", () => {
    const initialBinding = binding("2.0.0", "2.1.0", "1", "2", "3");
    const index = appendUpgradeHistoryEntry(undefined, initialBinding);
    expect(() => appendUpgradeHistoryEntry(index, binding("2.1.0", "2.2.0", "9", "4", "5"))).toThrow(
      expect.objectContaining({ code: "UPGRADE_HISTORY_CONTINUITY_MISMATCH" }),
    );
    expect(() => appendUpgradeHistoryEntry(index, initialBinding)).toThrow(expect.objectContaining({ code: "UPGRADE_HISTORY_DUPLICATE" }));
    const mutated = { ...structuredClone(index), entries: index.entries.map((entry, position) =>
      position === 0 ? { ...entry, currentPackSha256: "f".repeat(64) } : entry) };
    expect(() => parseUpgradeHistoryIndex(mutated)).toThrow(expect.objectContaining({ code: "UPGRADE_HISTORY_INTEGRITY_INVALID" }));
  });

  it("orders prereleases before their final release", () => {
    expect(() => appendUpgradeHistoryEntry(undefined, binding("2.0.0-rc.1", "2.0.0", "1", "2", "3"))).not.toThrow();
    expect(() => appendUpgradeHistoryEntry(undefined, binding("2.0.0", "2.0.0-rc.1", "1", "2", "3"))).toThrow(
      expect.objectContaining({ code: "UPGRADE_HISTORY_VERSION_ORDER_INVALID" }),
    );
  });
});
