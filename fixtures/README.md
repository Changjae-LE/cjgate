# CJGate test fixtures

Inputs for `npm run cjgate:check:test` (and manual `npm run cjgate:check -- --source fixtures/<name>`).

| Fixture            | Contents                                              | Scanner  | Expected policy |
| ----------------- | ---------------------------------------------------- | -------- | --------------- |
| `fixtures/clean`  | Ordinary config/source files.                        | —        | **PASS**        |
| `fixtures/secret` | One **deliberately fake** credential-shaped string.  | Gitleaks | **BLOCK**       |
| `fixtures/sast`   | One **intentionally vulnerable** demo source file.   | Semgrep  | **BLOCK**       |

## About `fixtures/secret`

The value in `fixtures/secret/` is **synthetic and not a real credential**. It
is a made-up string in the shape of a token so that Gitleaks flags it, letting
us verify the BLOCK path end to end. It grants access to nothing.

## About `fixtures/sast`

`fixtures/sast/` contains **intentionally vulnerable demonstration code** (an
OS command injection) so Semgrep produces an `ERROR`-severity finding. It holds
no credentials or sensitive data.

## Whole-repo scans

The repository-root `.gitleaks.toml` allow-lists `fixtures/secret/` and
`fixtures/sast/`, and `npm run cjgate:check` passes matching `--exclude` globs
to Semgrep, so a whole-repo scan is not tripped by the fixtures. Scanning a
fixture directory directly (as the fixture test does) still detects it.
