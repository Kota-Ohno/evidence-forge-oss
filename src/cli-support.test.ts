import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { formatCliError, formatCliErrorEnvelope, option, options, pathOption, runCli } from "./cli-support.js";
import { DiagnosticError } from "./diagnostics.js";

describe("CLI support", () => {
  it("reads scalar, repeated, and resolved path options", () => {
    const arguments_ = ["--name", "one", "--item", "a", "--item", "b", "--path", "./fixture"];
    expect(option(arguments_, "name")).toBe("one");
    expect(options(arguments_, "item")).toEqual(["a", "b"]);
    expect(pathOption(arguments_, "path")).toBe(resolve("./fixture"));
    expect(() => option(["--name", "--other"], "name")).toThrow("Missing --name");
  });

  it("redacts resolved local paths without treating short values as patterns", () => {
    const raw = "./private/report.json";
    const absolute = resolve(raw);
    expect(formatCliError(
      new Error(`Cannot read ${absolute}`), ["--report", raw], ["report"], "Failed",
    )).toBe("Failed: Cannot read [local file]");
    expect(formatCliError(new Error("data unavailable"), ["--report", "a"], ["report"], "Failed"))
      .toBe("Failed: data unavailable");
  });

  it("emits a stable diagnostic code while redacting local paths", () => {
    const raw = "./private/archive.json";
    const absolute = resolve(raw);
    expect(formatCliError(
      new DiagnosticError("ARCHIVE_PACK_MISSING", `Cannot read ${absolute}`),
      ["--pack", raw], ["pack"], "Audit failed", "ARCHIVE_AUDIT_OPERATION_FAILED",
    )).toBe("Audit failed [ARCHIVE_PACK_MISSING]: Cannot read [local file]");
    expect(formatCliError(
      new Error("Invalid JSON"), [], [], "Audit failed", "ARCHIVE_AUDIT_OPERATION_FAILED",
    )).toBe("Audit failed [ARCHIVE_AUDIT_OPERATION_FAILED]: Invalid JSON");
  });

  it("emits a closed bounded JSON error envelope on explicit opt-in", async () => {
    const raw = "./private/archive.json";
    const absolute = resolve(raw);
    const envelope = formatCliErrorEnvelope(
      new DiagnosticError("ARCHIVE_PACK_MISSING", `${absolute}:${"界".repeat(2_000)}`),
      ["--pack", raw], ["pack"], "ARCHIVE_AUDIT_OPERATION_FAILED",
    );
    expect(envelope).toMatchObject({
      version: 1, kind: "EvidenceForgeCliError", outcome: "error", code: "ARCHIVE_PACK_MISSING",
    });
    expect(envelope.message).toContain("[local file]");
    expect(Buffer.byteLength(envelope.message)).toBeLessThanOrEqual(4 * 1024);
    const schema = JSON.parse(readFileSync(new URL("../schemas/cli-error.schema.json", import.meta.url), "utf8")) as {
      additionalProperties: boolean; required: string[];
    };
    expect(schema.additionalProperties).toBe(false);
    expect(schema.required).toEqual(["version", "kind", "outcome", "code", "message"]);

    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const previousExitCode = process.exitCode;
    try {
      await runCli(() => { throw new DiagnosticError("ARCHIVE_PACK_MISSING", `Cannot read ${absolute}`); }, {
        arguments: ["audit", "--pack", raw, "--error-format", "json"], help: "Usage: audit",
        pathOptions: ["pack"], errorPrefix: "Audit failed", fallbackErrorCode: "ARCHIVE_AUDIT_OPERATION_FAILED",
      });
      expect(JSON.parse(String(write.mock.calls[0]?.[0]))).toEqual({
        version: 1, kind: "EvidenceForgeCliError", outcome: "error", code: "ARCHIVE_PACK_MISSING",
        message: "Cannot read [local file]",
      });
      expect(process.exitCode).toBe(1);
    } finally {
      process.exitCode = previousExitCode;
      write.mockRestore();
    }
  });
});
