import { assertPrivateTrace } from "./dogfood-stack.mjs";

const event = (eventType, overrides = {}) => ({
  eventType,
  security: { contentMode: "metadata_only", sensitivity: "private" },
  payload: eventType === "command.finished" ? { exitCode: 0 } : {},
  ...overrides,
});
const safeEvents = () => [event("command.started"), event("command.finished"), event("command.started"), event("command.finished")];

export const FAILURE_MATRIX = [
  { name: "retained_content", trace: () => `${safeEvents().map(JSON.stringify).join("\n")}\nDO_NOT_RETAIN`, forbidden: ["DO_NOT_RETAIN"], error: /forbidden content/u },
  { name: "raw_content_mode", trace: () => safeEvents().map((item, index) => JSON.stringify(index === 0 ? { ...item, security: { ...item.security, contentMode: "raw" } } : item)).join("\n"), forbidden: [], error: /unsupported content mode/u },
  { name: "public_sensitivity", trace: () => safeEvents().map((item, index) => JSON.stringify(index === 0 ? { ...item, security: { ...item.security, sensitivity: "public" } } : item)).join("\n"), forbidden: [], error: /non-private event/u },
  { name: "incomplete_lifecycle", trace: () => safeEvents().slice(0, 3).map(JSON.stringify).join("\n"), forbidden: [], error: /Expected 4 lifecycle events/u },
  { name: "wrong_event_type", trace: () => safeEvents().map((item, index) => JSON.stringify(index === 0 ? { ...item, eventType: "tool.started" } : item)).join("\n"), forbidden: [], error: /complete command lifecycles/u },
  { name: "failed_command", trace: () => safeEvents().map((item, index) => JSON.stringify(index === 1 ? { ...item, payload: { exitCode: 1 } } : item)).join("\n"), forbidden: [], error: /did not finish successfully/u },
  { name: "malformed_json", trace: () => `not-json\n${safeEvents().slice(1).map(JSON.stringify).join("\n")}`, forbidden: [], error: /Unexpected token/u },
];

export function verifyFailureMatrix() {
  const results = FAILURE_MATRIX.map((fixture) => {
    try {
      assertPrivateTrace(fixture.trace(), fixture.forbidden);
      throw new Error(`${fixture.name} was accepted`);
    } catch (error) {
      if (!fixture.error.test(error instanceof Error ? error.message : String(error))) throw error;
      return { name: fixture.name, outcome: "rejected" };
    }
  });
  return { version: 1, total: results.length, passed: results.length, results };
}

if (import.meta.url === new URL(process.argv[1] ?? "", "file:").href) {
  process.stdout.write(`${JSON.stringify(verifyFailureMatrix(), null, 2)}\n`);
}
