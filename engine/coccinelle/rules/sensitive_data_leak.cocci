// sensitive_data_leak.cocci — Review secret-named buffers at release.
// Names are sensitivity hints, not evidence that secret bytes are present.
// Recognize clearing requests with the standard argument roles, excluding
// known zero-length calls. Size coverage and compiler retention need review.
// kfree_sensitive clears the allocation itself and is not an uncleared release.
// memset_s uses (destination, capacity, value, count); memset_explicit
// follows the ordinary memset signature.
// https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf
// https://www.kernel.org/doc/html/latest/core-api/mm-api.html
// @role: detection
// raptor: confirm-only
// A non-secret identifier does not prove that a buffer contains no secret data.

@sensitive_zero_length@
expression BUF, VALUE, SIZE, LENGTH;
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position zero_pos;
@@
(
  \(memset\|memset_explicit\)(BUF, VALUE, ZERO)@zero_pos;
|
  memset_s(BUF, SIZE, VALUE, ZERO)@zero_pos;
|
  memset_s(BUF, ZERO, VALUE, LENGTH)@zero_pos;
|
  \(explicit_bzero\|memzero_explicit\|OPENSSL_cleanse\|sodium_memzero\)(BUF, ZERO)@zero_pos;
)

// Zero stores and zero-byte operations cannot introduce new buffer contents.
@sensitive_zero_only@
expression BUF, INDEX, SIZE, LENGTH;
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position zero_store;
@@
(
BUF =@zero_store \( ZERO \| NULL \);
|
BUF[INDEX] =@zero_store \( ZERO \| '\0' \);
|
  (*BUF) =@zero_store \( ZERO \| '\0' \);
|
  \(memset\|memset_explicit\)(BUF, \( ZERO \| '\0' \), LENGTH)@zero_store;
|
memset_s(BUF, SIZE, \( ZERO \| '\0' \), LENGTH)@zero_store;
|
  \(memcpy\|memmove\|memset\|memset_explicit\)(BUF, ..., ZERO)@zero_store;
|
memset_s(BUF, SIZE, ..., ZERO)@zero_store;
)

@sensitive_free exists@
identifier V =~ "\(^\|_\)\(key\|pass\|secret\|token\|cred\|master\)\|privkey\|priv_key\|private_key";
identifier CONTEXT;
expression BUFFER;
position p;
@@
(
* \(free\|kfree\|vfree\)(V@BUFFER)@p;
|
* \(free\|kfree\|vfree\)(CONTEXT->V@BUFFER)@p;
|
* \(free\|kfree\|vfree\)(CONTEXT.V@BUFFER)@p;
)

@uncleared_entry exists@
identifier FUNC;
expression sensitive_free.BUFFER;
position sensitive_free.p;
expression RELEASE;
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position wipe != sensitive_zero_length.zero_pos;
@@
FUNC(...) {
... when any
    when != \(memset\|memset_explicit\)(BUFFER, \( ZERO \| '\0' \), ...)@wipe
    when != memset_s(BUFFER, ..., \( ZERO \| '\0' \), ...)@wipe
    when != \(explicit_bzero\|memzero_explicit\|OPENSSL_cleanse\|sodium_memzero\)(BUFFER, ...)@wipe
    when != BUFFER = NULL
    when != BUFFER = ZERO
RELEASE(BUFFER)@p;
... when any
}

@contents_changed exists@
expression sensitive_free.BUFFER;
position sensitive_free.p;
expression RELEASE;
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position wipe != sensitive_zero_length.zero_pos;
expression FN, ALIAS;
identifier NAME;
type T;
assignment operator op;
position changed != sensitive_zero_only.zero_store;
@@
(
BUFFER op@changed ...;
|
BUFFER++;
|
  ++BUFFER;
|
BUFFER--;
|
  --BUFFER;
|
BUFFER[...] op@changed ...;
|
BUFFER[...]++;
|
  ++BUFFER[...];
|
BUFFER[...]--;
|
  --BUFFER[...];
|
  (*BUFFER) op@changed ...;
|
FN(..., &BUFFER, ...);
|
FN(..., &BUFFER[...], ...);
|
ALIAS = &BUFFER;
|
T NAME = &BUFFER;
|
  \(memset\|memset_explicit\|memset_s\|memcpy\|memmove\)(BUFFER, ...)@changed;
)
... when any
    when != \(memset\|memset_explicit\)(BUFFER, \( ZERO \| '\0' \), ...)@wipe
    when != memset_s(BUFFER, ..., \( ZERO \| '\0' \), ...)@wipe
    when != \(explicit_bzero\|memzero_explicit\|OPENSSL_cleanse\|sodium_memzero\)(BUFFER, ...)@wipe
    when != BUFFER = NULL
    when != BUFFER = ZERO
RELEASE(BUFFER)@p;

@field_context_changed exists@
identifier sensitive_free.CONTEXT;
expression sensitive_free.BUFFER;
position sensitive_free.p;
expression RELEASE;
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position wipe != sensitive_zero_length.zero_pos;
assignment operator op;
expression FN;
@@
(
CONTEXT op ...;
|
CONTEXT++;
|
  ++CONTEXT;
|
CONTEXT--;
|
  --CONTEXT;
|
FN(..., &CONTEXT, ...);
)
... when any
    when != \(memset\|memset_explicit\)(BUFFER, \( ZERO \| '\0' \), ...)@wipe
    when != memset_s(BUFFER, ..., \( ZERO \| '\0' \), ...)@wipe
    when != \(explicit_bzero\|memzero_explicit\|OPENSSL_cleanse\|sodium_memzero\)(BUFFER, ...)@wipe
    when != BUFFER = NULL
    when != BUFFER = ZERO
RELEASE(BUFFER)@p;

@script:python sensitive_report depends on sensitive_free && (uncleared_entry || contents_changed || field_context_changed)@
p << sensitive_free.p;
V << sensitive_free.V;
@@
import json
# English words that start with an anchored component but carry no
# secret: the regex cannot express "key but not keyboard" (no word
# boundaries in this syntax), so the residue is dropped here —
# per underscore-component, so compounds (keyboard_state,
# usb_keyboard, keyframes) are absorbed too, and prefix-matched so
# plurals are covered. A name is benign only when EVERY component
# that carries a secret anchor is a benign word; the explicit
# privkey spellings match the rule regex without any anchored
# component and never consult this set.
_benign = ("keyboard", "keycode", "keymap", "keypad", "keysym",
           "keyword", "keyframe", "keyval", "passthrough", "passthru",
           "tokenizer", "tokenize")
_secret = ("key", "pass", "secret", "token", "cred", "master")
_carriers = [c for c in str(V).lower().split("_")
             if c.startswith(_secret)]
if not (_carriers and all(any(c.startswith(b) for b in _benign)
                          for c in _carriers)):
    msg = {
      "rule":  "sensitive_data_leak",
      "file":  p[0].file,
      "line":  int(p[0].line),
      "col":   int(p[0].column),
      "message":   "Candidate: secret-named buffer released without an uninterrupted recognized clearing request; review sensitivity, wipe range, aliases and compiler retention (CWE-244)."
    }
    print("COCCIRESULT:" + json.dumps(msg))
