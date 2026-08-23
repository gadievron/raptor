// ssl-unpin.js - bypass common SSL/TLS certificate pinning paths.
//
// Originally drafted by @ZephrFish for the v2 Frida integration.
// Splinters will likely supersede with a richer version pulling
// from his closed PR #57; this is the starter.
//
// Targets covered:
//   * iOS:     SecTrustEvaluateWithError / SecTrustGetTrustResult
//              (Security.framework - modern path)
//   * macOS:   same as iOS via Security.framework
//   * OpenSSL: SSL_get_verify_result, SSL_CTX_set_verify
//   * Android: javax.net.ssl.X509TrustManager.checkServerTrusted
//              (only if a Java VM is attached)
//
// Each bypass emits a {category, fn, before, after} record so the
// operator sees *which* pinning layer fired and was overridden.
//
// Use:
//   raptor frida --target com.example.app --template ssl-unpin --usb
//   raptor frida --target Safari --template ssl-unpin

'use strict';

function emit(category, fn, detail) {
  send({ category: category, fn: fn, detail: detail });
}

// ─── Security.framework (iOS / macOS) ───────────────────────────────
(function patchSecurityFramework() {
  const symbols = [
    // newer API, returns bool
    { name: 'SecTrustEvaluateWithError', retType: 'bool' },
    // older API, returns OSStatus
    { name: 'SecTrustEvaluate', retType: 'OSStatus' },
  ];
  for (const sym of symbols) {
    const addr = Module.findExportByName('Security', sym.name);
    if (addr === null) continue;
    Interceptor.attach(addr, {
      onLeave: function (retval) {
        if (sym.retType === 'bool') {
          // SecTrustEvaluateWithError returns true on success
          if (retval.toInt32() === 0) {
            emit('ssl-unpin', sym.name, { forced: 'true' });
            retval.replace(1);
          }
        } else {
          // SecTrustEvaluate returns errSecSuccess (0) on success.
          // Force result to kSecTrustResultProceed (1) via out-param -
          // here we just zero the return code which is sufficient for
          // most NSURLSession pinning paths.
          if (retval.toInt32() !== 0) {
            emit('ssl-unpin', sym.name, {
              forced: 'errSecSuccess', original: retval.toInt32(),
            });
            retval.replace(0);
          }
        }
      },
    });
    emit('ssl-unpin', '_hook_installed', { sym: sym.name });
  }
})();

// ─── OpenSSL ────────────────────────────────────────────────────────
(function patchOpenSSL() {
  // Frida 17 removed Module.findExportByName(null, ...). Use the
  // global search helper when present.
  const findGlobal = (typeof Module.findGlobalExportByName === 'function')
    ? Module.findGlobalExportByName.bind(Module)
    : function (n) { try { return Module.findExportByName(null, n); } catch (_e) { return null; } };
  const addr = findGlobal('SSL_get_verify_result');
  if (addr === null) return;
  Interceptor.attach(addr, {
    onLeave: function (retval) {
      // X509_V_OK is 0; force pass.
      if (retval.toInt32() !== 0) {
        emit('ssl-unpin', 'SSL_get_verify_result', {
          forced: 'X509_V_OK', original: retval.toInt32(),
        });
        retval.replace(0);
      }
    },
  });
  emit('ssl-unpin', '_hook_installed', { sym: 'SSL_get_verify_result' });
})();

// ─── Android JSSE (only if Java is available) ───────────────────────
if (typeof Java !== 'undefined' && Java.available) {
  Java.perform(function () {
    try {
      const X509TM = Java.use('javax.net.ssl.X509TrustManager');
      X509TM.checkServerTrusted.overload(
        '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
      ).implementation = function (chain, authType) {
        emit('ssl-unpin', 'X509TrustManager.checkServerTrusted', {
          authType: authType, chainLen: chain.length,
        });
        // Return without throwing → certificate accepted.
      };
      emit('ssl-unpin', '_hook_installed', {
        sym: 'X509TrustManager.checkServerTrusted',
      });
    } catch (e) {
      emit('ssl-unpin', '_hook_failed', { err: String(e) });
    }
  });
}

send({ _meta: 'ssl-unpin loaded' });
