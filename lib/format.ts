// format.ts — pretty printing for decoded jwts.

import type { DecodedJwt } from "./decode.ts";

const TIMESTAMP_KEYS = new Set(["iat", "exp", "nbf"]);

const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

export interface FormatOptions {
  color?: boolean;
  now?: number; // seconds, for testing
}

/** unix seconds -> "YYYY-MM-DD HH:MM:SS UTC" */
export function formatUnixTimestamp(sec: number): string {
  if (!Number.isFinite(sec)) return "";
  const d = new Date(sec * 1000);
  if (isNaN(d.getTime())) return "";
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${
    pad(d.getUTCHours())
  }:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

/** human-ish duration like "1h", "3d", "45m" from seconds. */
export function formatDuration(sec: number): string {
  const s = Math.abs(Math.round(sec));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) {
    const h = s / 3600;
    return Number.isInteger(h) ? `${h}h` : `${h.toFixed(1)}h`;
  }
  const d = s / 86400;
  return Number.isInteger(d) ? `${d}d` : `${d.toFixed(1)}d`;
}

export function isExpired(payload: Record<string, unknown>, nowSec: number): boolean {
  const exp = payload["exp"];
  return typeof exp === "number" && exp < nowSec;
}

function padRight(s: string, width: number): string {
  return s.length >= width ? s : s + " ".repeat(width - s.length);
}

function renderValue(v: unknown): string {
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number" || typeof v === "boolean" || v === null) {
    return String(v);
  }
  // objects/arrays — compact json
  return JSON.stringify(v);
}

function renderSection(
  title: string,
  obj: Record<string, unknown>,
  opts: FormatOptions,
  extraAnnotate?: (key: string, value: unknown) => string | null,
): string {
  const lines: string[] = [`${title}:`];
  const keys = Object.keys(obj);
  const keyWidth = keys.reduce((m, k) => Math.max(m, k.length), 0);
  for (const k of keys) {
    const v = obj[k];
    let line = `  ${padRight(k, keyWidth)}  ${renderValue(v)}`;
    if (TIMESTAMP_KEYS.has(k) && typeof v === "number") {
      const ts = formatUnixTimestamp(v);
      if (ts) line += `  ${opts.color ? DIM : ""}(${ts})${opts.color ? RESET : ""}`;
    }
    const extra = extraAnnotate?.(k, v);
    if (extra) line += ` ${extra}`;
    lines.push(line);
  }
  return lines.join("\n");
}

export function formatDecoded(decoded: DecodedJwt, opts: FormatOptions = {}): string {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const expired = isExpired(decoded.payload, now);

  const headerText = renderSection("header", decoded.header, opts);

  const iat = decoded.payload["iat"];
  const payloadText = renderSection("payload", decoded.payload, opts, (k, v) => {
    if (k === "exp" && typeof v === "number") {
      if (typeof iat === "number") {
        const delta = v - iat;
        return `, ${formatDuration(delta)} from iat`;
      }
      if (expired) {
        return `, expired ${formatDuration(now - v)} ago`;
      }
    }
    return null;
  });

  // wrap exp line in red if expired
  let payloadRendered = payloadText;
  if (expired && opts.color) {
    payloadRendered = payloadText
      .split("\n")
      .map((line) => line.trimStart().startsWith("exp ") ? `${RED}${line}${RESET}` : line)
      .join("\n");
  }

  const sigBytes = decoded.signatureBytes.length;
  const sigLine = sigBytes === 0
    ? `signature: (empty) — alg=none or unsigned`
    : `signature: base64(${sigBytes} bytes) — not verified`;

  return `${headerText}\n\n${payloadRendered}\n\n${sigLine}`;
}

export function formatJson(decoded: DecodedJwt): string {
  return JSON.stringify(
    {
      header: decoded.header,
      payload: decoded.payload,
      signature: decoded.signature,
    },
    null,
    2,
  );
}
