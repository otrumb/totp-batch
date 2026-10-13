# totp-batch

Offline TOTP code generation for one secret or a strictly validated JSON Lines
batch. Runtime uses Python standard library only.

## Publication boundary

Source target: <https://github.com/otrumb/totp-batch>. No PyPI package, package
publication, tag, or release exists or is authorized.

## Usage

```console
totp-batch
printf '<BASE32_SECRET>\n' | totp-batch --stdin
printf '{"label":"synthetic-1","secret":"<BASE32_SECRET>"}\n' | totp-batch --stdin
printf '{"label":"synthetic-1","secret":"<BASE32_SECRET>"}\n' | totp-batch --stdin --json
python -m totp_batch --help
```

Examples contain placeholders, not usable credentials or generated codes. Default
mode reads exactly one Base32 secret through a hidden prompt. `--stdin` must be
explicit and redirected. Leading whitespace followed by `{` selects JSON Lines;
all other input selects one Base32 line. Do not put secrets in argv, environment
variables, paths, filenames, or URIs.

## JSON Lines input

Input schema identity is `totp-batch/input/v1`; each physical line is one flat JSON
object with exactly these supported fields:

| Field | Type | Required | Default | Contract |
| --- | --- | --- | --- | --- |
| `label` | string | yes | none | ASCII grammar `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` |
| `secret` | string | yes | none | canonical Base32, padded or unpadded, decoding to 16..64 bytes |
| `algorithm` | string | no | `SHA1` | `SHA1`, `SHA256`, or `SHA512` |
| `digits` | integer | no | `6` | `6` or `8` |
| `period` | integer | no | `30` | 1..86400 seconds |

Unknown or duplicate JSON keys, comments, blank lines, nested values, booleans,
floating-point values, BOM input, and trailing content are rejected. Batch limits:
1..100 records, 2048 bytes per line, and 256 KiB total. Labels are unique under
case-folding. Decoded secrets must also be unique. Whole batch validates before
generation, so invalid final record produces no partial standard output.

Single-line stdin permits one optional final LF or CRLF and no surrounding content.
Hidden and single-stdin modes use SHA1, 6 digits, and 30-second period.

## Output contracts

Plain single output is code plus newline. Plain batch output is one
`label<TAB>code<LF>` record per input record. `--json` emits compact ASCII JSON:

```json
{"schema":"totp-batch/output/v1","codes":[{"label":"synthetic-1","code":"<GENERATED_CODE>","generated_at":0,"window_start":0,"window_end":30}]}
```

`label` is `null` for single input. Times are integer Unix seconds. Output never
contains input secret, URI, or fingerprint.

| Exit | Meaning |
| --- | --- |
| `0` | success or help |
| `1` | output or operating-system failure |
| `2` | usage, input, or generation boundary failure |
| `130` | interruption or unavailable hidden input |

Errors intentionally produce no diagnostic carrying secret material. Closed or
broken standard output exits 1 without traceback.

## Security limits

Codes depend on local device clock. Tool does not contact server, measure clock
skew, or compensate for drift. TOTP is not phishing resistant.

Secrets and codes can be exposed by terminal display, standard-output consumers,
pipes, redirection, terminal scrollback, process memory, swap, and crash dumps.
Python cannot guarantee erasure of immutable secret objects. Hidden entry prevents
terminal echo only; it does not remove these wider exposures.

NIST password composition guidance is not relevant as a strength claim for TOTP.
RFC 4226 and RFC 6238 define algorithm context and public vectors. Google
Authenticator's `otpauth://` URI convention is context only and remains excluded.

## Excluded scope

No `otpauth://` parsing, file configuration, storage, network access, QR handling,
clipboard integration, watch mode, HOTP mode, code verification, secret generation,
telemetry, or server-skew measurement.

## Development

```console
uv sync --locked --all-groups
uv run ruff format --check .
uv run ruff check .
uv run basedpyright
uv run pytest
uv run python -m compileall -q src tests
uv build
```
