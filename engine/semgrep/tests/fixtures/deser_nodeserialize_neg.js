// unserialize() on a receiver that is NOT node-serialize: a project's
// own codec must not mint a CRITICAL RCE verdict by method name alone.
const codec = require("./safe-codec");

function fromStore(raw) {
  return codec.unserialize(raw);
}

class TokenCodec {
  unserialize(raw) {
    return JSON.parse(raw);
  }
}

function viaInstance(c, raw) {
  return c.unserialize(raw);
}
