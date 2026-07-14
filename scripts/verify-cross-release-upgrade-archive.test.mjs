import assert from "node:assert/strict";
import test from "node:test";
import { parseCrossReleaseUpgradeArguments } from "./verify-cross-release-upgrade-archive.mjs";

test("cross-release upgrade acceptance requires ordered external anchors", () => {
  const args = [];
  for (let index = 0; index < 3; index += 1) args.push(
    "--release-pack", `./v${String(index + 1)}.json`,
    "--release-pack-sha256", String(index + 1).repeat(64),
    "--release-key-id", String(index + 4).repeat(64),
  );
  args.push("--output", "./result");
  const parsed = parseCrossReleaseUpgradeArguments(args);
  assert.equal(parsed.releases.length, 3);
  assert.match(parsed.output, /result$/u);
  assert.deepEqual(parseCrossReleaseUpgradeArguments(["--help"]), { help: true });
  assert.throws(() => parseCrossReleaseUpgradeArguments(args.slice(0, -8).concat(["--output", "./bad"])), /3-8 equal ordered/u);
  assert.throws(() => parseCrossReleaseUpgradeArguments(args.map((value) => value === "./v2.json" ? "./v1.json" : value)), /must be unique/u);
});
