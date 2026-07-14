import assert from "node:assert/strict";
import test from "node:test";
import { parseGitleaksVersion, SECRET_SCAN_ARGUMENTS } from "./audit-secrets.mjs";

test("secret audit recognizes a bounded semantic scanner version", () => {
  assert.equal(parseGitleaksVersion("8.30.1\n"), "8.30.1");
  assert.throws(() => parseGitleaksVersion("gitleaks latest"), /unrecognized version/u);
});

test("secret audit scans history and working tree with mandatory redaction", () => {
  assert.equal(SECRET_SCAN_ARGUMENTS.gitHistory[0], "git");
  assert.equal(SECRET_SCAN_ARGUMENTS.workingTree[0], "dir");
  for (const arguments_ of Object.values(SECRET_SCAN_ARGUMENTS)) {
    assert.ok(arguments_.includes("--redact"));
    assert.ok(arguments_.includes("--no-color"));
    assert.equal(arguments_.at(-1), ".");
    assert.equal(arguments_.some((argument) => argument.startsWith("--report")), false);
  }
});
