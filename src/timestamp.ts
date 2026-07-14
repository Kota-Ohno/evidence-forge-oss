import { PromotionError } from "./domain.js";

const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-](\d{2}):(\d{2})))?$/u;

function daysInMonth(year: number, month: number): number {
  const lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as const;
  if (month === 2 && (year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0))) return 29;
  return lengths[month - 1] ?? 0;
}

export function parseTimestamp(value: string, { allowDateOnly = false } = {}): bigint {
  const match = TIMESTAMP.exec(value);
  if (!match || (!allowDateOnly && match[4] === undefined)) invalid(value);
  const yearText = match[1];
  const monthText = match[2];
  const dayText = match[3];
  if (yearText === undefined || monthText === undefined || dayText === undefined) invalid(value);
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = match[4] === undefined ? 0 : Number(match[4]);
  const minute = match[5] === undefined ? 0 : Number(match[5]);
  const second = match[6] === undefined ? 0 : Number(match[6]);
  const offsetHour = match[9] === undefined ? 0 : Number(match[9]);
  const offsetMinute = match[10] === undefined ? 0 : Number(match[10]);
  const base = match[4] === undefined
    ? `${value}T00:00:00Z`
    : value.replace(/\.\d{1,9}(?=Z|[+-])/u, "");
  const parsed = Date.parse(base);
  if (
    month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) ||
    hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59 ||
    !Number.isFinite(parsed)
  ) invalid(value);
  const fraction = (match[7] ?? "").padEnd(9, "0");
  return BigInt(parsed) * 1_000_000n + BigInt(fraction || "0");
}

function invalid(value: string): never {
  throw new PromotionError("INVALID_TIMESTAMP", `Invalid timestamp: ${value}`);
}
