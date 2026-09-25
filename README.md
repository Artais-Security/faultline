# faultline

A probe for **OWASP Top 10:2025 A10 - Mishandling of Exceptional Conditions**.

`faultline` throws a battery of malformed and unexpected inputs at a web
endpoint and analyzes the responses for signs the application mishandles
exceptional conditions: verbose error / stack-trace disclosure, sensitive
information leakage in errors, unhandled server-side exceptions, and error
handling that diverges from a clean baseline.

Single-file, standard-library-only, Python 3.8+. No third-party dependencies.

## Why A10

A10:2025 is a new category in the 2025 revision, focused on the *root cause*
rather than a symptom: applications that fail to anticipate abnormal states and
leak internals (or fall over) when they hit one. It is a strong fit for
black-box probing because the tells are all in the response.

## Install

No install step. Drop the file somewhere on `PATH` and mark it executable:

```
cp faultline.py /usr/local/bin/faultline
chmod +x /usr/local/bin/faultline
```

## Usage

```
faultline https://target/api/item?id=1
faultline https://target/api/item -X POST -d '{"id":1,"q":"x"}' -H 'Authorization: Bearer ...'
faultline https://target/api/item?id=1 --json -o findings.json --fail-on medium
```

`faultline` sends a baseline request first, then compares every probe response
against it. Query parameters present in the URL are fuzzed individually; if
`--data` is valid JSON, each top-level field is fuzzed with both value-level and
type-confusion payloads. Body- and header-level probes (malformed JSON,
content-type mismatches, oversized bodies) run regardless.

### Common options

| Option | Purpose |
| --- | --- |
| `-X, --method` | HTTP method (a `--data` body implies a body-bearing method) |
| `-d, --data` | request body; fuzzed per-field when it parses as JSON |
| `-H, --header` | extra header, repeatable (`'Name: value'`) |
| `--delay` | pause between requests; be kind to live targets |
| `--max-requests` | cap total probe requests |
| `--fail-on` | minimum severity that sets exit code 1 (default: `low`) |
| `-k, --insecure` | skip TLS certificate verification |
| `--json` | machine-readable output |
| `-o, --output` | write findings to a file |
| `--baseline-only` | send only the baseline request, then report |
| `-v, --verbose` | stream findings as they are discovered |

## What it detects

- Interactive debuggers left exposed (Werkzeug, Rails web-console) - highest severity
- Framework debug pages and stack traces (Django, ASP.NET, Java, PHP, Python, Node, Ruby)
- SQL / datastore error messages
- Filesystem path, internal host / private IP, and connection-string disclosure
- Unhandled server errors (5xx) triggered by malformed input where the baseline succeeded

Findings are ranked `critical` > `high` > `medium` > `low` > `info`. A generic
exception keyword on its own is treated as low signal unless the server also
errored.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | completed, no findings at/above the `--fail-on` threshold |
| 1 | findings at/above the `--fail-on` threshold |
| 2 | usage error, or the target could not be reached at all |

Suitable for CI gating: set `--fail-on` to the severity that should break a build.

## Scope and safety

`faultline` sends deliberately malformed traffic and can trigger server-side
errors. Only run it against systems you are authorized to assess. Use `--delay`
and `--max-requests` on production or fragile targets.

## Extending

The probe catalog (`value_probes`, `json_structural_probes`, `request_probes`)
and the detection `SIGNATURES` table are the two extension points. Add a payload
or a signature row; nothing else needs to change.

## License

CC BY 4.0 (documentation) / see `LICENSE` for tool code terms.
