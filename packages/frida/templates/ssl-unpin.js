/**
 * RAPTOR Frida Template: SSL Certificate Pinning Bypass
 *
 * Bypasses SSL certificate pinning on multiple platforms:
 * - iOS (NSURLSession, CFNetwork)
 * - Android (OkHttp, Apache HTTP, WebView)
 * - Generic (OpenSSL, BoringSSL, GnuTLS)
 */

function log(message, level = 'info') {
    send({
        level: level,
        message: message
    });
}

function sendFinding(title, severity, details) {
    send({
        type: 'finding',
        level: severity,
        title: title,
        details: details,
        timestamp: Date.now()
    });
}

log('SSL Unpinning started', 'info');

// iOS SSL Pinning Bypass
if (ObjC.available) {
    log('iOS detected - hooking SSL verification', 'info');

    // NSURLSession
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
        const delegate = ObjC.classes.NSURLSessionDataDelegate;
        if (delegate) {
            Interceptor.attach(
                ObjC.classes.NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'].implementation,
                {
                    onEnter: function(args) {
                        log('NSURLSession challenge intercepted', 'warning');
                        sendFinding(
                            'SSL Pinning Bypassed',
                            'warning',
                            'NSURLSession certificate validation bypassed'
                        );
                    }
                }
            );
        }
    }

    // Disable SSL kill switch detection
    const SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
    if (SSLSetSessionOption) {
        Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
            return 0; // Success
        }, 'int', ['pointer', 'int', 'int']));
        log('SSLSetSessionOption bypassed', 'info');
    }
}

// Android SSL Pinning Bypass
if (Java.available) {
    Java.perform(function() {
        log('Android detected - hooking SSL verification', 'info');

        // OkHttp3 pinning bypass
        try {
            const OkHttpClient = Java.use('okhttp3.OkHttpClient');
            const CertificatePinner = Java.use('okhttp3.CertificatePinner');

            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                log('OkHttp3 CertificatePinner.check() bypassed', 'warning');
                sendFinding(
                    'SSL Pinning Bypassed',
                    'warning',
                    'OkHttp3 certificate pinning bypassed'
                );
            };
        } catch (e) {
            log('OkHttp3 not found: ' + e, 'info');
        }

        // TrustManager bypass
        try {
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');

            const TrustManager = Java.registerClass({
                name: 'com.raptor.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            const TrustManagers = [TrustManager.$new()];
            const SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );

            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
                log('SSLContext.init() bypassed with custom TrustManager', 'warning');
            };
        } catch (e) {
            log('TrustManager bypass failed: ' + e, 'info');
        }

        // WebView SSL Error bypass
        try {
            const WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
                log('WebView SSL error bypassed', 'warning');
                handler.proceed();
                sendFinding(
                    'SSL Error Ignored',
                    'warning',
                    'WebView SSL error handler bypassed'
                );
            };
        } catch (e) {
            log('WebViewClient not found: ' + e, 'info');
        }
    });
}

// Generic SSL/TLS library bypasses
// OpenSSL
const SSL_CTX_set_verify = Module.findExportByName(null, 'SSL_CTX_set_verify');
if (SSL_CTX_set_verify) {
    Interceptor.replace(SSL_CTX_set_verify, new NativeCallback(function(ssl_ctx, mode, callback) {
        log('OpenSSL SSL_CTX_set_verify() bypassed', 'warning');
        sendFinding(
            'SSL Verification Disabled',
            'warning',
            'OpenSSL certificate verification disabled'
        );
        return;
    }, 'void', ['pointer', 'int', 'pointer']));
}

const SSL_get_verify_result = Module.findExportByName(null, 'SSL_get_verify_result');
if (SSL_get_verify_result) {
    Interceptor.replace(SSL_get_verify_result, new NativeCallback(function(ssl) {
        log('OpenSSL SSL_get_verify_result() bypassed', 'info');
        return 0; // X509_V_OK
    }, 'int', ['pointer']));
}

// BoringSSL (used by Chrome/Android)
const SSL_set_custom_verify = Module.findExportByName(null, 'SSL_set_custom_verify');
if (SSL_set_custom_verify) {
    Interceptor.replace(SSL_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
        log('BoringSSL SSL_set_custom_verify() bypassed', 'warning');
        return;
    }, 'void', ['pointer', 'int', 'pointer']));
}

// GnuTLS
const gnutls_certificate_verify_peers2 = Module.findExportByName(null, 'gnutls_certificate_verify_peers2');
if (gnutls_certificate_verify_peers2) {
    Interceptor.replace(gnutls_certificate_verify_peers2, new NativeCallback(function(session, status) {
        log('GnuTLS certificate verification bypassed', 'warning');
        Memory.writeU32(status, 0); // No errors
        return 0; // Success
    }, 'int', ['pointer', 'pointer']));
}

log('SSL Unpinning hooks installed', 'info');
sendFinding(
    'SSL Unpinning Active',
    'info',
    'All SSL/TLS certificate validation hooks have been installed'
);
