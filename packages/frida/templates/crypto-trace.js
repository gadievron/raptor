/**
 * RAPTOR Frida Template: Cryptographic Operations Tracing
 *
 * Traces crypto operations to identify:
 * - Weak algorithms (MD5, SHA1, DES, RC4)
 * - Hardcoded keys
 * - Predictable IVs
 * - Insecure random number generation
 */

function log(message, level = 'info') {
    send({ level: level, message: message });
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

log('Crypto tracer started', 'info');

// OpenSSL/BoringSSL hooks
const crypto_funcs = [
    'MD5_Init', 'MD5_Update', 'MD5_Final',
    'SHA1_Init', 'SHA1_Update', 'SHA1_Final',
    'DES_set_key', 'DES_ecb_encrypt',
    'RC4_set_key', 'RC4',
    'AES_set_encrypt_key', 'AES_encrypt',
    'EVP_EncryptInit_ex', 'EVP_DecryptInit_ex',
    'RAND_bytes'
];

crypto_funcs.forEach(function(func_name) {
    const func_ptr = Module.findExportByName(null, func_name);
    if (func_ptr) {
        Interceptor.attach(func_ptr, {
            onEnter: function(args) {
                log(`${func_name}() called`, 'info');

                // Warn about weak algorithms
                if (func_name.startsWith('MD5') || func_name.startsWith('SHA1')) {
                    sendFinding(
                        'Weak Hash Algorithm',
                        'warning',
                        `${func_name} uses cryptographically weak algorithm`
                    );
                }

                if (func_name.startsWith('DES') || func_name.startsWith('RC4')) {
                    sendFinding(
                        'Weak Cipher',
                        'error',
                        `${func_name} uses broken/weak encryption`
                    );
                }

                // Log key material (be careful with this!)
                if (func_name.includes('set_key')) {
                    const key_ptr = args[1] || args[0];
                    try {
                        const key_bytes = Memory.readByteArray(key_ptr, 16);
                        const key_hex = Array.from(new Uint8Array(key_bytes))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join('');
                        log(`Key material: ${key_hex.substring(0, 32)}...`, 'warning');
                    } catch (e) {
                        // Key not readable
                    }
                }
            }
        });
        log(`Hooked ${func_name}`, 'info');
    }
});

// Random number generation
const rand_bytes = Module.findExportByName(null, 'RAND_bytes');
if (rand_bytes) {
    Interceptor.attach(rand_bytes, {
        onEnter: function(args) {
            this.buf = args[0];
            this.num = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 1 && this.num > 0) {
                try {
                    const random_data = Memory.readByteArray(this.buf, Math.min(this.num, 32));
                    log(`RAND_bytes generated ${this.num} bytes`, 'info');
                } catch (e) {}
            }
        }
    });
}

log('Crypto tracing hooks installed', 'info');
