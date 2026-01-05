/**
 * RAPTOR Frida Template: Memory Scanning
 *
 * Scans process memory for:
 * - API keys, secrets, tokens
 * - Passwords and credentials
 * - Cryptographic material
 * - PII (emails, SSNs, credit cards)
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

log('Memory scanner started', 'info');

// Patterns to search for
const patterns = {
    'API Key (AWS)': /AKIA[0-9A-Z]{16}/g,
    'API Key (Generic)': /[aA][pP][iI][_]?[kK][eE][yY][\s:=]+['\"]?([a-zA-Z0-9_\-]{16,})['\"]?/g,
    'Private Key (RSA)': /-----BEGIN RSA PRIVATE KEY-----/g,
    'Private Key (EC)': /-----BEGIN EC PRIVATE KEY-----/g,
    'Password': /[pP][aA][sS][sS][wW][oO][rR][dD][\s:=]+['\"]?([^\s'\"]{8,})['\"]?/g,
    'JWT Token': /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    'Email': /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    'Credit Card': /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    'SSN': /\b\d{3}-\d{2}-\d{4}\b/g,
    'Bearer Token': /[bB]earer[\s]+[a-zA-Z0-9\-._~+\/]+=*/g
};

// Scan memory range
function scanMemoryRange(base, size, label) {
    try {
        const data = Memory.readByteArray(base, Math.min(size, 1024 * 1024)); // Max 1MB per scan
        if (!data) return;

        const text = hexToString(new Uint8Array(data));

        for (const [patternName, pattern] of Object.entries(patterns)) {
            const matches = text.match(pattern);
            if (matches && matches.length > 0) {
                log(`Found ${patternName} in ${label}`, 'warning');
                sendFinding(
                    `Sensitive Data in Memory: ${patternName}`,
                    'warning',
                    {
                        pattern: patternName,
                        location: label,
                        address: base.toString(),
                        sample: matches[0].substring(0, 100) // First 100 chars
                    }
                );
            }
        }
    } catch (e) {
        // Memory not readable, skip
    }
}

// Helper to convert bytes to string (tolerant of non-UTF8)
function hexToString(bytes) {
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i];
        if (byte >= 32 && byte <= 126) {
            result += String.fromCharCode(byte);
        } else {
            result += '.';
        }
    }
    return result;
}

// Scan all memory regions
log('Scanning process memory regions...', 'info');
Process.enumerateRanges('r--').forEach(function(range) {
    if (range.size > 0 && range.size < 10 * 1024 * 1024) { // Skip huge regions
        const label = range.file ? range.file.path : 'anonymous';
        scanMemoryRange(range.base, range.size, label);
    }
});

// Hook memory allocation to scan new allocations
const malloc = Module.findExportByName(null, 'malloc');
if (malloc) {
    Interceptor.attach(malloc, {
        onLeave: function(retval) {
            if (!retval.isNull()) {
                // Scan new allocations periodically (not all, too expensive)
                if (Math.random() < 0.01) { // 1% sample rate
                    const size = this.context.r0 || this.context.rdi; // Platform-dependent
                    if (size > 100 && size < 1024 * 1024) {
                        scanMemoryRange(retval, size, 'heap');
                    }
                }
            }
        }
    });
    log('Memory allocation hook installed', 'info');
}

// Hook string operations to catch sensitive data being processed
const strcpy = Module.findExportByName(null, 'strcpy');
if (strcpy) {
    Interceptor.attach(strcpy, {
        onEnter: function(args) {
            const src = Memory.readUtf8String(args[1]);
            if (src && src.length > 10) {
                // Check against patterns
                for (const [patternName, pattern] of Object.entries(patterns)) {
                    if (pattern.test(src)) {
                        sendFinding(
                            `Sensitive String Copy: ${patternName}`,
                            'warning',
                            {
                                pattern: patternName,
                                operation: 'strcpy',
                                sample: src.substring(0, 100)
                            }
                        );
                        break;
                    }
                }
            }
        }
    });
    log('String operation hooks installed', 'info');
}

log('Memory scanner hooks active', 'info');
