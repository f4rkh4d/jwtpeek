import { assertEquals, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { base64UrlDecode, decodeJwt, JwtShapeError } from "../lib/decode.ts";

// helper — encode json as base64url (for building test tokens)
function b64url(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

Deno.test("base64UrlDecode: handles standard input with no padding", () => {
  const bytes = base64UrlDecode(b64url("hello"));
  assertEquals(new TextDecoder().decode(bytes), "hello");
});

Deno.test("base64UrlDecode: handles url-safe chars (- and _)", () => {
  // bytes 0xfb 0xff 0xbf -> standard b64 "+/+/" -> url-safe "-_-_"
  const bytes = base64UrlDecode("-_-_");
  assertEquals(Array.from(bytes), [0xfb, 0xff, 0xbf]);
});

Deno.test("base64UrlDecode: rejects invalid chars", () => {
  assertThrows(() => base64UrlDecode("!!!!"), JwtShapeError);
});

Deno.test("decodeJwt: rejects empty string", () => {
  assertThrows(() => decodeJwt(""), JwtShapeError, "empty");
});

Deno.test("decodeJwt: rejects wrong number of parts", () => {
  assertThrows(() => decodeJwt("a.b"), JwtShapeError, "3 dot-separated");
  assertThrows(() => decodeJwt("a.b.c.d"), JwtShapeError, "3 dot-separated");
});

Deno.test("decodeJwt: rejects non-json header", () => {
  const bad = `${b64url("not-json")}.${b64url('{"a":1}')}.sig`;
  assertThrows(() => decodeJwt(bad), JwtShapeError, "header");
});

Deno.test("decodeJwt: rejects non-json payload", () => {
  const bad = `${b64url('{"alg":"none"}')}.${b64url("xxx")}.`;
  assertThrows(() => decodeJwt(bad), JwtShapeError, "payload");
});

Deno.test("decodeJwt: parses a valid token (HS256 shape)", () => {
  const h = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = b64url(JSON.stringify({ sub: "1234", name: "alice" }));
  const s = b64url("fakesig");
  const out = decodeJwt(`${h}.${p}.${s}`);
  assertEquals(out.header.alg, "HS256");
  assertEquals(out.payload.sub, "1234");
  assertEquals(out.payload.name, "alice");
  assertEquals(out.signatureBytes.length > 0, true);
});

Deno.test("decodeJwt: alg=none with empty signature", () => {
  const h = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
  const p = b64url(JSON.stringify({ sub: "1" }));
  const out = decodeJwt(`${h}.${p}.`);
  assertEquals(out.header.alg, "none");
  assertEquals(out.signatureBytes.length, 0);
});

Deno.test("decodeJwt: rejects header that decodes to array", () => {
  const h = b64url(JSON.stringify([1, 2, 3]));
  const p = b64url(JSON.stringify({ a: 1 }));
  assertThrows(
    () => decodeJwt(`${h}.${p}.sig`),
    JwtShapeError,
    "header",
  );
});

Deno.test("decodeJwt: trims surrounding whitespace", () => {
  const h = b64url(JSON.stringify({ alg: "HS256" }));
  const p = b64url(JSON.stringify({ sub: "x" }));
  const out = decodeJwt(`  ${h}.${p}.sig\n`);
  assertEquals(out.payload.sub, "x");
});
