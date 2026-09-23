// sensitive_data_leak.cocci — Detect sensitive buffers freed without
// being zeroed first.
//
// Cryptographic keys, passwords, and session tokens remain in freed
// memory until the allocator reuses the page. An information
// disclosure primitive (e.g. uninitialised read, /proc/kcore) can
// recover the secret. Always use memset_s/explicit_bzero/memzero_explicit
// before freeing.
//
// CWE-244: Improper Clearing of Heap Data Before Release
// Matching heuristic: variable or field name carries a secret-bearing
// word (key/pass/secret/token/cred/master) at the start of the name or
// of an underscore-separated component. Anchoring matters: substring
// matching turned every driver-private-data pointer (`priv` — the
// single most common context-pointer name in driver code) and every
// benign carrier of an embedded word (bypass, monkey) into a CWE-244
// finding. Bare `priv`/`*_priv` never matches now; only the explicit
// private-key spellings do. A small deny-set in the report script
// drops full English words that legitimately start with an anchored
// component (keyboard, passthrough, ...), applied per
// underscore-separated component so compounds (keyboard_state) are
// absorbed while a real secret component beside a benign one
// (keyboard_master_key) still reports.
// @role: detection

@sensitive_free@
identifier V =~ "\(^\|_\)\(key\|pass\|secret\|token\|cred\|master\)\|privkey\|priv_key\|private_key";
position p;
@@

* \(free\|kfree\|kfree_sensitive\|vfree\)(V)@p;

@ok_cleared@
identifier sensitive_free.V;
position sensitive_free.p;
@@

  \(memset\|memset_s\|explicit_bzero\|memzero_explicit\|OPENSSL_cleanse\|sodium_memzero\)(V, ...);
  ... when != V = ...
  \(free\|kfree\|kfree_sensitive\|vfree\)(V)@p;

@script:python sensitive_report depends on sensitive_free && !ok_cleared@
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
      "message":   "Sensitive buffer freed without clearing — secret data persists in freed memory (CWE-244). Use memset_s/explicit_bzero before free."
    }
    print("COCCIRESULT:" + json.dumps(msg))
