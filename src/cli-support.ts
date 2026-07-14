import { resolve } from "node:path";
import { diagnosticCode, diagnosticError } from "./diagnostics.js";

const MAX_JSON_MESSAGE_BYTES = 4 * 1024;
const GENERIC_ERROR_CODE = "CLI_OPERATION_FAILED";

export interface CliErrorEnvelope {
  readonly version: 1;
  readonly kind: "EvidenceForgeCliError";
  readonly outcome: "error";
  readonly code: string;
  readonly message: string;
}

export interface CliRunnerOptions {
  readonly arguments: readonly string[];
  readonly help: string;
  readonly pathOptions?: readonly string[];
  readonly errorPrefix: string;
  readonly fallbackErrorCode?: string;
}

export function option(arguments_: readonly string[], name: string): string {
  const index = arguments_.indexOf(`--${name}`);
  const value = index < 0 ? undefined : arguments_[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`Missing --${name}`);
  return value;
}

export function options(arguments_: readonly string[], name: string): string[] {
  const flag = `--${name}`;
  return arguments_.flatMap((argument, index) => argument === flag && arguments_[index + 1] &&
    !arguments_[index + 1]?.startsWith("--") ? [arguments_[index + 1] as string] : []);
}

export function pathOption(arguments_: readonly string[], name: string): string {
  return resolve(option(arguments_, name));
}

export function pathOptions(arguments_: readonly string[], name: string): string[] {
  return options(arguments_, name).map((value) => resolve(value));
}

export function formatCliError(
  error: unknown,
  arguments_: readonly string[],
  pathOptionNames: readonly string[],
  prefix: string,
  fallbackCode?: string,
): string {
  const message = redactedCliMessage(error, arguments_, pathOptionNames);
  return `${prefix}${fallbackCode ? ` [${diagnosticCode(error, fallbackCode)}]` : ""}: ${message}`;
}

export function formatCliErrorEnvelope(
  error: unknown,
  arguments_: readonly string[],
  pathOptionNames: readonly string[],
  fallbackCode = GENERIC_ERROR_CODE,
): CliErrorEnvelope {
  return {
    version: 1,
    kind: "EvidenceForgeCliError",
    outcome: "error",
    code: diagnosticCode(error, fallbackCode),
    message: boundUtf8(redactedCliMessage(error, arguments_, pathOptionNames), MAX_JSON_MESSAGE_BYTES),
  };
}

function redactedCliMessage(error: unknown, arguments_: readonly string[], pathOptionNames: readonly string[]): string {
  let message = error instanceof Error ? error.message : String(error);
  const paths = pathOptionNames.flatMap((name) => options(arguments_, name))
    .map((path) => resolve(path))
    .sort((left, right) => right.length - left.length);
  for (const path of paths) message = message.replaceAll(path, "[local file]");
  return message;
}

export async function runCli(main: () => void | Promise<void>, runner: CliRunnerOptions): Promise<void> {
  if (runner.arguments.includes("--help") || runner.arguments.includes("-h")) {
    process.stdout.write(`${runner.help.trimEnd()}\nError output option: --error-format json\n`);
    return;
  }
  try {
    const errorFormats = options(runner.arguments, "error-format");
    if (errorFormats.length > 1 || (errorFormats.length === 1 && errorFormats[0] !== "json") ||
        (runner.arguments.includes("--error-format") && errorFormats.length === 0)) {
      throw diagnosticError("CLI_ERROR_FORMAT_INVALID", "--error-format must be specified once with value json");
    }
    await main();
  } catch (error) {
    if (options(runner.arguments, "error-format").includes("json")) {
      process.stderr.write(`${JSON.stringify(formatCliErrorEnvelope(
        error, runner.arguments, runner.pathOptions ?? [], runner.fallbackErrorCode,
      ))}\n`);
    } else {
      process.stderr.write(`${formatCliError(
        error, runner.arguments, runner.pathOptions ?? [], runner.errorPrefix, runner.fallbackErrorCode,
      )}\n`);
    }
    process.exitCode = 1;
  }
}

function boundUtf8(value: string, maximumBytes: number): string {
  if (Buffer.byteLength(value) <= maximumBytes) return value;
  let result = "", bytes = 0;
  for (const character of value) {
    const size = Buffer.byteLength(character);
    if (bytes + size + Buffer.byteLength("…") > maximumBytes) return `${result}…`;
    result += character;
    bytes += size;
  }
  return result;
}
