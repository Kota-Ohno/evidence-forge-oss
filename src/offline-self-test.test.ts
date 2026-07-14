import { existsSync, readFileSync, statSync } from "node:fs";
import Ajv2020Import from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { describe, expect, it } from "vitest";
import { runOfflineInstalledSelfTestWithHarness } from "./offline-self-test.js";

describe("offline installed self-test", () => {
  it("exercises the core local flow and removes its private workspace", async () => {
    let root = "", rootMode = 0;
    const result = await runOfflineInstalledSelfTestWithHarness({ rootObserved: (value) => {
      root = value; rootMode = statSync(value).mode;
    } });
    expect(root).not.toBe("");
    expect(rootMode & 0o077).toBe(0);
    expect(existsSync(root)).toBe(false);
    expect(result).toMatchObject({
      kind: "EvidenceForgeOfflineInstalledSelfTest", outcome: "verified",
      captureVerified: true, promotionVerified: true, packetRoundTripVerified: true,
      capabilitiesVerified: true, networkAccessed: false, databaseOpened: false,
      listenerOpened: false, temporaryBytesRetained: false, timestampAttested: false,
    });
    expect(JSON.stringify(result)).not.toContain(root);
    expect(JSON.stringify(result)).not.toContain("exact local citation");
    const schema = JSON.parse(readFileSync(new URL(
      "../schemas/offline-installed-self-test.schema.json", import.meta.url,
    ), "utf8")) as AnySchema;
    const contract = schema as { additionalProperties: boolean; required: string[]; properties: Record<string, unknown> };
    expect(contract.additionalProperties).toBe(false);
    expect(contract.required).toEqual(Object.keys(result));
    expect(Object.keys(contract.properties)).toEqual(Object.keys(result));
    const Ajv2020 = Ajv2020Import.default;
    expect(new Ajv2020({ strict: true }).compile(schema)(result)).toBe(true);
  });

  it("removes its workspace when a partial run fails", async () => {
    let root = "";
    await expect(runOfflineInstalledSelfTestWithHarness({
      rootObserved: (value) => { root = value; },
      afterCapture: () => { throw new Error("injected self-test failure"); },
    })).rejects.toThrow("injected self-test failure");
    expect(root).not.toBe("");
    expect(existsSync(root)).toBe(false);
  });
});
