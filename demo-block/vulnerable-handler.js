// =============================================================================
//  INTENTIONALLY VULNERABLE DEMONSTRATION CODE — DO NOT USE
//
//  This file exists only so Semgrep has a real ERROR-severity finding when
//  CJGate's SAST BLOCK path is tested. It contains a textbook OS command
//  injection. There are no credentials or sensitive data here.
// =============================================================================

const { exec } = require('child_process');

// VULNERABLE: untrusted input concatenated into a shell command string.
function listDirectory(req, res) {
  const target = req.query.path;
  exec('ls -la ' + target, (err, stdout) => {
    res.end(stdout);
  });
}

module.exports = { listDirectory };
