/**
 * RAPTOR Frida Template: API Tracing
 *
 * Traces common API calls for security analysis:
 * - File operations
 * - Network operations
 * - Process/system calls
 * - Crypto operations
 */

// Helper to send findings back to Python
function sendFinding(title, severity, details) {
    send({
        type: 'finding',
        level: severity,
        title: title,
        details: details,
        timestamp: Date.now()
    });
}

// Helper to log messages
function log(message, level = 'info') {
    send({
        level: level,
        message: message
    });
}

log('API Tracing started', 'info');

// Trace file operations
if (Process.platform === 'darwin' || Process.platform === 'linux') {
    // POSIX file operations
    const fopen = Module.findExportByName(null, 'fopen');
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                const path = Memory.readUtf8String(args[0]);
                const mode = Memory.readUtf8String(args[1]);
                log(`fopen("${path}", "${mode}")`, 'info');

                if (path.includes('passwd') || path.includes('shadow')) {
                    sendFinding(
                        'Sensitive File Access',
                        'warning',
                        `Attempt to open sensitive file: ${path}`
                    );
                }
            }
        });
    }

    // Network - connect
    const connect = Module.findExportByName(null, 'connect');
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                const sockaddr = args[1];
                log('connect() called', 'info');
            }
        });
    }

    // Process execution
    const system = Module.findExportByName(null, 'system');
    if (system) {
        Interceptor.attach(system, {
            onEnter: function(args) {
                const cmd = Memory.readUtf8String(args[0]);
                log(`system("${cmd}")`, 'warning');
                sendFinding(
                    'Command Execution',
                    'warning',
                    `system() called with: ${cmd}`
                );
            }
        });
    }

    // Memory allocation (for tracking large allocations)
    const malloc = Module.findExportByName(null, 'malloc');
    if (malloc) {
        Interceptor.attach(malloc, {
            onEnter: function(args) {
                const size = args[0].toInt32();
                if (size > 10 * 1024 * 1024) {  // > 10MB
                    log(`Large malloc: ${size} bytes`, 'warning');
                }
            }
        });
    }
}

// Windows-specific APIs
if (Process.platform === 'windows') {
    // File operations
    const createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
    if (createFileW) {
        Interceptor.attach(createFileW, {
            onEnter: function(args) {
                const filename = Memory.readUtf16String(args[0]);
                log(`CreateFileW("${filename}")`, 'info');
            }
        });
    }

    // Registry operations
    const regOpenKeyExW = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
    if (regOpenKeyExW) {
        Interceptor.attach(regOpenKeyExW, {
            onEnter: function(args) {
                const keyName = Memory.readUtf16String(args[1]);
                log(`RegOpenKeyExW("${keyName}")`, 'info');
            }
        });
    }

    // Process creation
    const createProcessW = Module.findExportByName('kernel32.dll', 'CreateProcessW');
    if (createProcessW) {
        Interceptor.attach(createProcessW, {
            onEnter: function(args) {
                const appName = args[0].isNull() ? '' : Memory.readUtf16String(args[0]);
                const cmdLine = args[1].isNull() ? '' : Memory.readUtf16String(args[1]);
                log(`CreateProcessW: ${appName} ${cmdLine}`, 'warning');
                sendFinding(
                    'Process Creation',
                    'warning',
                    `CreateProcessW called: ${appName} ${cmdLine}`
                );
            }
        });
    }
}

log('API Tracing hooks installed', 'info');
