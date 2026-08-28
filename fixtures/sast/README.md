# SAST fixture

`vulnerable-handler.js` is **intentionally vulnerable demonstration code**. It
contains an OS command injection so that Semgrep produces an `ERROR`-severity
finding, letting the CJGate SAST BLOCK path be tested end to end.

It holds no credentials or sensitive data. Do not copy it into real code.

`npm run cjgate:check` excludes `fixtures/sast` from a whole-repo scan;
scanning this directory directly (as the fixture test does) still detects it.
