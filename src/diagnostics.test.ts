import { describe, expect, it } from "vitest";
import { DiagnosticError, diagnosticCode } from "./diagnostics.js";

describe("stable diagnostics", () => {
  it("accepts bounded internal codes and falls back for ordinary errors", () => {
    const error = new DiagnosticError("RELEASE_INDEX_HEAD_MISMATCH", "mismatch");
    expect(diagnosticCode(error, "RELEASE_INDEX_OPERATION_FAILED")).toBe("RELEASE_INDEX_HEAD_MISMATCH");
    expect(diagnosticCode(new Error("invalid"), "RELEASE_INDEX_OPERATION_FAILED")).toBe("RELEASE_INDEX_OPERATION_FAILED");
  });

  it("rejects malformed diagnostic identifiers", () => {
    expect(() => new DiagnosticError("bad-code", "invalid")).toThrow("3-64 uppercase");
    expect(() => diagnosticCode(new Error("invalid"), "bad-code")).toThrow("Fallback diagnostic code is invalid");
  });
});
