import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  REVIEW_HTML,
  REVIEW_JAVASCRIPT,
  REVIEW_SCRIPT_ASSETS,
  REVIEW_STYLE_ASSETS,
  REVIEW_STYLES,
} from "./review-assets.js";

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

describe("Review Workspace assets", () => {
  it("composes the browser contract in a deterministic order", () => {
    expect(REVIEW_STYLES).toBe(REVIEW_STYLE_ASSETS.join(""));
    expect(REVIEW_JAVASCRIPT).toBe(REVIEW_SCRIPT_ASSETS.join(""));
    expect(REVIEW_STYLE_ASSETS).toHaveLength(13);
    expect(REVIEW_SCRIPT_ASSETS).toHaveLength(14);
  });

  it("pins the M115 browser asset bytes", () => {
    expect(sha256(REVIEW_HTML)).toBe("e3bac0437c069930f871438cbdef9fc98b71116850379558eacfeaf620aa207a");
    expect(sha256(REVIEW_STYLES)).toBe("dba3565ba7331bcd51ac1c0528ca30e1d4a7be65523e05a395ccc4ef1a9cc7ec");
    expect(sha256(REVIEW_JAVASCRIPT)).toBe("8c6bf4a4e27670c6a636b9be120c866db894f887da928c34b100bc5871bbbb84");
    expect(REVIEW_JAVASCRIPT.match(/fetch\('\/api\/review-bootstrap'\)/gu)).toHaveLength(1);
    expect(REVIEW_JAVASCRIPT).not.toMatch(/fetch\('\/api\/(?:stack-history|archive-inventory|upgrade-inventory|coverage-readiness|workspace-acceptance|lineage-continuity)'\)/u);
    expect(REVIEW_JAVASCRIPT).not.toContain("MutationObserver");
  });
});
