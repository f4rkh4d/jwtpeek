// decode.ts — jwt decoding helpers. no signature verification, just base64url stuff.

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string; // raw base64url signature part (as given)
  signatureBytes: Uint8Array; // decoded bytes
  raw: { header: string; payload: string; signature: string };
}

export class JwtShapeError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "JwtShapeError";
  }
}

/** base64url -> bytes. handles missing padding. */
export function base64UrlDecode(input: string): Uint8Array {
  if (typeof input !== "string") {
    throw new JwtShapeError("base64url input must be a string");
  }
  // strip whitespace
  const trimmed = input.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9_\-]*$/.test(trimmed)) {
    throw new JwtShapeError("invalid base64url characters");
  }
  // translate to standard base64
  let b64 = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  // pad
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  else if (pad === 1) throw new JwtShapeError("invalid base64url length");

  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function base64UrlDecodeToString(input: string): string {
  return new TextDecoder().decode(base64UrlDecode(input));
}

/** split & decode a JWT. throws JwtShapeError on bad shape. */
export function decodeJwt(token: string): DecodedJwt {
  if (typeof token !== "string" || token.length === 0) {
    throw new JwtShapeError("empty token");
  }
  const t = token.trim();
  const parts = t.split(".");
  if (parts.length !== 3) {
    throw new JwtShapeError(
      `expected 3 dot-separated parts, got ${parts.length}`,
    );
  }
  const [h, p, s] = parts;
  if (h.length === 0 || p.length === 0) {
    throw new JwtShapeError("header or payload is empty");
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(base64UrlDecodeToString(h));
  } catch (_e) {
    throw new JwtShapeError("header is not valid json");
  }
  try {
    payload = JSON.parse(base64UrlDecodeToString(p));
  } catch (_e) {
    throw new JwtShapeError("payload is not valid json");
  }
  if (typeof header !== "object" || header === null || Array.isArray(header)) {
    throw new JwtShapeError("header must decode to an object");
  }
  if (
    typeof payload !== "object" || payload === null || Array.isArray(payload)
  ) {
    throw new JwtShapeError("payload must decode to an object");
  }

  // signature can be empty for alg=none. we don't verify it, so be lenient —
  // if it's not valid base64url we just treat it as 0 bytes and keep the raw string.
  let sigBytes: Uint8Array = new Uint8Array(0);
  if (s.length > 0) {
    try {
      sigBytes = base64UrlDecode(s);
    } catch (_e) {
      sigBytes = new Uint8Array(0);
    }
  }

  return {
    header,
    payload,
    signature: s,
    signatureBytes: sigBytes,
    raw: { header: h, payload: p, signature: s },
  };
}
