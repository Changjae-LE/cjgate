# CJGate test fixtures

Inputs for `npm run cjgate:check:test` (and manual `npm run cjgate:check -- --source fixtures/<name>`).

| Fixture            | Contents                                              | Expected policy |
| ----------------- | ---------------------------------------------------- | --------------- |
| `fixtures/clean`  | Ordinary config/source files, no secrets.            | **PASS**        |
| `fixtures/secret` | One **deliberately fake** credential-shaped string.  | **BLOCK**       |

## About `fixtures/secret`

The value in `fixtures/secret/` is **synthetic and not a real credential**. It
is a made-up string in the shape of a token so that Gitleaks flags it, letting
us verify the BLOCK path end to end. It grants access to nothing.

The repository-root `.gitleaks.toml` allow-lists `fixtures/secret/` so a normal
`npm run cjgate:check` of the whole repo is not tripped by it. Scanning that
directory directly (as the fixture test does) still detects it.
