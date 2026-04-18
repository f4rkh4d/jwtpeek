import { assertEquals, assertStringIncludes } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { formatDecoded, formatDuration, formatUnixTimestamp, isExpired } from "../lib/format.ts";
import type { DecodedJwt } from "../lib/decode.ts";

Deno.test("formatUnixTimestamp: formats a known epoch", () => {
  // 2024-04-05 12:34:38 UTC
  const out = formatUnixTimestamp(1712320478);
  assertEquals(out, "2024-04-05 12:34:38 UTC");
});

Deno.test("formatUnixTimestamp: returns empty for non-finite", () => {
  assertEquals(formatUnixTimestamp(NaN), "");
  assertEquals(formatUnixTimestamp(Infinity), "");
});

Deno.test("formatDuration: handles seconds/minutes/hours/days", () => {
  assertEquals(formatDuration(30), "30s");
  assertEquals(formatDuration(120), "2m");
  assertEquals(formatDuration(3600), "1h");
  assertEquals(formatDuration(86400 * 2), "2d");
});

Deno.test("isExpired: true when exp is past", () => {
  assertEquals(isExpired({ exp: 100 }, 200), true);
  assertEquals(isExpired({ exp: 500 }, 200), false);
  assertEquals(isExpired({}, 200), false);
});

function makeDecoded(payload: Record<string, unknown>): DecodedJwt {
  return {
    header: { alg: "HS256", typ: "JWT" },
    payload,
    signature: "sig",
    signatureBytes: new Uint8Array([1, 2, 3]),
    raw: { header: "h", payload: "p", signature: "sig" },
  };
}

Deno.test("formatDecoded: includes header and payload sections", () => {
  const out = formatDecoded(
    makeDecoded({ sub: "1234", name: "alice" }),
    { now: 1712320478, color: false },
  );
  assertStringIncludes(out, "header:");
  assertStringIncludes(out, "payload:");
  assertStringIncludes(out, "HS256");
  assertStringIncludes(out, "alice");
  assertStringIncludes(out, "not verified");
});

Deno.test("formatDecoded: annotates iat/exp with human time", () => {
  const out = formatDecoded(
    makeDecoded({ iat: 1712320478, exp: 1712324078 }),
    { now: 1712320500, color: false },
  );
  assertStringIncludes(out, "2024-04-05");
  assertStringIncludes(out, "from iat");
});

Deno.test("formatDecoded: shows expired note when exp is past and no iat", () => {
  const out = formatDecoded(
    makeDecoded({ exp: 100 }),
    { now: 1000, color: false },
  );
  assertStringIncludes(out, "expired");
});

Deno.test("formatDecoded: red ansi code wraps expired line when color=true", () => {
  const out = formatDecoded(
    makeDecoded({ exp: 100 }),
    { now: 1000, color: true },
  );
  // red escape
  assertStringIncludes(out, "\x1b[31m");
});

Deno.test("formatDecoded: handles alg=none empty signature", () => {
  const d: DecodedJwt = {
    header: { alg: "none" },
    payload: { sub: "x" },
    signature: "",
    signatureBytes: new Uint8Array(0),
    raw: { header: "h", payload: "p", signature: "" },
  };
  const out = formatDecoded(d, { color: false });
  assertStringIncludes(out, "empty");
});
