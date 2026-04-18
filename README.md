# jwtpeek

decode and inspect jwts from the cli. doesnt verify, just shows whats inside.

wrote this bc every other jwt tool wants a secret key to do anything. sometimes i just wanna know
whats in the token. thats it.

## install

via `deno install` (might not be on deno.land/x yet, so `deno run` works as a fallback):

```sh
deno install -g --allow-env -n jwtpeek https://deno.land/x/jwtpeek/cli.ts
```

or just run it directly from the repo:

```sh
deno run https://raw.githubusercontent.com/f4rkh4d/jwtpeek/main/cli.ts <TOKEN>
```

local clone:

```sh
git clone https://github.com/f4rkh4d/jwtpeek
cd jwtpeek
deno task start <TOKEN>
# or compile a binary
deno task compile
./jwtpeek <TOKEN>
```

## usage

```sh
# stdin
echo "$TOKEN" | jwtpeek

# positional
jwtpeek eyJhbGciOi...

# flag
jwtpeek --token eyJhbGciOi...

# raw json
jwtpeek --json <TOKEN>

# just one part
jwtpeek --part payload <TOKEN>
jwtpeek --part header <TOKEN>
```

## example

```
$ echo $TOKEN | jwtpeek
header:
  alg  "HS256"
  typ  "JWT"

payload:
  sub    "1234567890"
  name   "alice"
  iat    1712345678  (2024-04-05 12:34:38 UTC)
  exp    1712349278  (2024-04-05 13:34:38 UTC), 1h from iat
  roles  ["admin","user"]

signature: base64(32 bytes) — not verified
```

expired tokens get highlighted in red. `alg=none` tokens decode fine too (for debugging).

## flags

| flag                                | what                |
| ----------------------------------- | ------------------- |
| `--token STRING`                    | token value         |
| `--json`                            | raw decoded output  |
| `--part header\|payload\|signature` | print just one part |
| `--no-color`                        | disable ansi colors |
| `-h, --help`                        | help                |
| `-V, --version`                     | version             |

exits `2` if the input isnt a valid jwt shape.

## dev

```sh
deno task test
deno fmt --check
deno lint
```

no runtime deps. tests use deno std assert.

## license

MIT — farkhad
