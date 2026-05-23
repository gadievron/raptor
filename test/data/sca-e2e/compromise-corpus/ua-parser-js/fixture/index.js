// Minimal consumer of ua-parser-js so SCA's reachability layer
// flips the verdict from ``not_reachable`` to ``imported`` —
// proves the import-detection layer correctly recognises CommonJS
// require() of the malicious dep.
const UAParser = require('ua-parser-js');

function detectBrowser(uaString) {
  const parser = new UAParser(uaString);
  return parser.getResult();
}

module.exports = { detectBrowser };
