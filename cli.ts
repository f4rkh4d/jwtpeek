#!/usr/bin/env -S deno run
// jwtpeek cli — decode jwts without verifying. just peek inside.

import { decodeJwt, JwtShapeError } from "./lib/decode.ts";
import { formatDecoded, formatJson } from "./lib/format.ts";

const USAGE = `jwtpeek — decode and inspect a jwt (no signature verification)

usage:
  jwtpeek [TOKEN] [flags]
  echo "$TOKEN" | jwtpeek

flags:
  --token STRING         token to decode (alt to positional / stdin)
  --json                 output raw decoded json
  --part PART            only output one part: header | payload | signature
  --no-color             disable ansi colors
  -h, --help             show this help
  -V, --version          show version

exit codes:
  0  ok
  2  input is not a valid jwt shape
`;

const VERSION = "0.1.0";

interface Args {
  token?: string;
  json: boolean;
  part?: "header" | "payload" | "signature";
  color: boolean;
  help: boolean;
  version: boolean;
  positional: string[];
}

function parseArgs(argv: string[]): Args {
  const out: Args = {
    json: false,
    color: true,
    help: false,
    version: false,
    positional: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--version" || a === "-V") out.version = true;
    else if (a === "--json") out.json = true;
    else if (a === "--no-color") out.color = false;
    else if (a === "--token") {
      const v = argv[++i];
      if (!v) throw new Error("--token needs a value");
      out.token = v;
    } else if (a.startsWith("--token=")) {
      out.token = a.slice("--token=".length);
    } else if (a === "--part") {
      const v = argv[++i];
      if (v !== "header" && v !== "payload" && v !== "signature") {
        throw new Error("--part must be header | payload | signature");
      }
      out.part = v;
    } else if (a.startsWith("--part=")) {
      const v = a.slice("--part=".length);
      if (v !== "header" && v !== "payload" && v !== "signature") {
        throw new Error("--part must be header | payload | signature");
      }
      out.part = v;
    } else if (a.startsWith("-")) {
      throw new Error(`unknown flag: ${a}`);
    } else {
      out.positional.push(a);
    }
  }
  return out;
}

async function readAllStdin(): Promise<string> {
  const chunks: Uint8Array[] = [];
  const buf = new Uint8Array(4096);
  while (true) {
    const n = await Deno.stdin.read(buf);
    if (n === null) break;
    chunks.push(buf.slice(0, n));
  }
  let total = 0;
  for (const c of chunks) total += c.length;
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.length;
  }
  return new TextDecoder().decode(merged);
}

function isTty(): boolean {
  try {
    // @ts-ignore: isTerminal is available in deno 1.40+
    return Deno.stdin.isTerminal?.() ?? false;
  } catch (_e) {
    return false;
  }
}

export async function main(argv: string[]): Promise<number> {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    console.error(`error: ${(e as Error).message}`);
    console.error(USAGE);
    return 2;
  }

  if (args.help) {
    console.log(USAGE);
    return 0;
  }
  if (args.version) {
    console.log(`jwtpeek ${VERSION}`);
    return 0;
  }

  let token = args.token ?? args.positional[0];
  if (!token && !isTty()) {
    token = (await readAllStdin()).trim();
  }
  if (!token) {
    console.error("error: no token provided (pass via stdin, arg, or --token)");
    console.error(USAGE);
    return 2;
  }

  let decoded;
  try {
    decoded = decodeJwt(token);
  } catch (e) {
    if (e instanceof JwtShapeError) {
      console.error(`error: not a valid jwt — ${e.message}`);
      return 2;
    }
    throw e;
  }

  // color default: on if stdout is tty AND not disabled
  let color = args.color;
  try {
    // @ts-ignore: isTerminal
    if (!Deno.stdout.isTerminal?.()) color = false;
  } catch (_e) {
    color = false;
  }

  if (args.part) {
    if (args.part === "header") {
      console.log(JSON.stringify(decoded.header, null, 2));
    } else if (args.part === "payload") {
      console.log(JSON.stringify(decoded.payload, null, 2));
    } else {
      console.log(decoded.signature);
    }
    return 0;
  }

  if (args.json) {
    console.log(formatJson(decoded));
    return 0;
  }

  console.log(formatDecoded(decoded, { color }));
  return 0;
}

if (import.meta.main) {
  const code = await main(Deno.args);
  if (code !== 0) Deno.exit(code);
}
