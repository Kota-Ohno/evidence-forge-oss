import { PromotionError } from "./domain.js";

const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-](\d{2}):(\d{2})))?$/u;

function daysInMonth(year: number, month: number): number {
  const lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as const;
  if (month === 2 && (year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0))) return 29;
  return lengths[month - 1] ?? 0;
}

export function parseTimestamp(value: string, { allowDateOnly = false } = {}): number {
  const match = TIMESTAMP.exec(value);
  if (!match || (!allowDateOnly && match[4] === undefined)) invalid(value);
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = match[4] === undefined ? 0 : Number(match[4]);
  const minute = match[5] === undefined ? 0 : Number(match[5]);
  const second = match[6] === undefined ? 0 : Number(match[6]);
  const offsetHour = match[9] === undefined ? 0 : Number(match[9]);
  const offsetMinute = match[10] === undefined ? 0 : Number(match[10]);
  const parsed = Date.parse(value);
  if (
    month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) ||
    hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59 ||
    !Number.isFinite(parsed)
  ) invalid(value);
  return parsed;
}

function invalid(value: string): never {
  throw new PromotionError("INVALID_TIMESTAMP", `Invalid timestamp: ${value}`);
}
