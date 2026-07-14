import { describe, expect, it } from "vitest";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { parseReleaseUpgradeBinding } from "./release-upgrade-binding.js";

function fixture() {
  const digest = (digit: string) => digit.repeat(64);
  const payload = {
    version: 1 as const, kind: "EvidenceForgeReleaseUpgradeBindingReceipt" as const,
    releases: {
      previous: { packageVersion: "2.0.0", packSha256: digest("1"), packageSha256: digest("2") },
      current: { packageVersion: "2.1.0", packSha256: digest("3"), packageSha256: digest("4") },
    },
    upgradeEvidence: {
      evidenceSha256: digest("5"), receiptSha256: digest("6"),
      previousManifestSha256: digest("7"), currentManifestSha256: digest("8"),
    },
    binding: { manifestsReproduced: true as const, lifecycleScripts: "disabled" as const },
    assurance: { timestamp: "not-attested" as const, packageCodeExecution: "capabilities-binary" as const },
  };
  return { ...payload, integrity: { algorithm: "sha256-jcs" as const, bindingSha256: canonicalJsonSha256(payload) } };
}

describe("release upgrade binding receipt", () => {
  it("parses a closed integrity-protected receipt", () => {
    expect(parseReleaseUpgradeBinding(fixture())).toEqual(fixture());
  });

  it("rejects mutation and unknown fields", () => {
    const mutated = fixture();
    mutated.releases.current.packageVersion = "2.2.0";
    expect(() => parseReleaseUpgradeBinding(mutated)).toThrow(expect.objectContaining({ code: "UPGRADE_BINDING_INTEGRITY_INVALID" }));
    expect(() => parseReleaseUpgradeBinding({ ...fixture(), localPath: "/tmp/leak" })).toThrow(
      expect.objectContaining({ code: "UPGRADE_BINDING_SCHEMA_INVALID" }),
    );
  });
});
