/**
 * RAPTOR Frida Template: Binary Environment Analysis
 *
 * Comprehensive binary execution context analysis:
 * - Loaded libraries and dependencies
 * - Symlinks and TOCTOU vulnerabilities
 * - LD_PRELOAD opportunities
 * - Environment variables
 * - File descriptors and IPC
 * - SUID/SGID binaries
 * - Dynamic linker behavior
 * - Syscall monitoring
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

log('Binary environment analysis started', 'info');

// ============================================================================
// 1. ENUMERATE LOADED LIBRARIES
// ============================================================================

log('Enumerating loaded libraries...', 'info');
const loadedLibraries = [];

Process.enumerateModules().forEach(function(module) {
    loadedLibraries.push({
        name: module.name,
        base: module.base.toString(),
        size: module.size,
        path: module.path
    });

    log(`Library loaded: ${module.name} at ${module.base}`, 'info');

    // Check for known vulnerable libraries
    const vulnLibs = ['libcrypto.so.1.0', 'libssl.so.1.0', 'libc.so.6'];
    if (vulnLibs.some(lib => module.name.includes(lib))) {
        sendFinding(
            'Potentially Vulnerable Library',
            'warning',
            {
                library: module.name,
                path: module.path,
                reason: 'Known vulnerable library version'
            }
        );
    }
});

send({ type: 'libraries', data: loadedLibraries });

// ============================================================================
// 2. HOOK DYNAMIC LINKER (LD.SO)
// ============================================================================

log('Hooking dynamic linker...', 'info');

// Hook dlopen() - Library loading
const dlopen = Module.findExportByName(null, 'dlopen');
if (dlopen) {
    Interceptor.attach(dlopen, {
        onEnter: function(args) {
            const lib = Memory.readUtf8String(args[0]);
            this.lib = lib;
            log(`dlopen("${lib}")`, 'warning');
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                sendFinding(
                    'Dynamic Library Loaded',
                    'info',
                    {
                        library: this.lib,
                        handle: retval.toString(),
                        method: 'dlopen'
                    }
                );
            }
        }
    });
    log('dlopen() hooked', 'info');
}

// Hook dlsym() - Symbol resolution
const dlsym = Module.findExportByName(null, 'dlsym');
if (dlsym) {
    Interceptor.attach(dlsym, {
        onEnter: function(args) {
            const symbol = Memory.readUtf8String(args[1]);
            this.symbol = symbol;

            // Check for dangerous functions
            const dangerousFuncs = ['system', 'exec', 'popen', 'fork', 'setuid'];
            if (dangerousFuncs.includes(symbol)) {
                sendFinding(
                    'Dangerous Function Resolution',
                    'warning',
                    {
                        symbol: symbol,
                        method: 'dlsym',
                        risk: 'Potential privilege escalation or command injection'
                    }
                );
            }
        }
    });
}

// ============================================================================
// 3. MONITOR FILE OPERATIONS (TOCTOU)
// ============================================================================

log('Monitoring file operations for TOCTOU...', 'info');

const fileOps = {};

// Track access() calls (check)
const access_ptr = Module.findExportByName(null, 'access');
if (access_ptr) {
    Interceptor.attach(access_ptr, {
        onEnter: function(args) {
            const path = Memory.readUtf8String(args[0]);
            const mode = args[1].toInt32();

            this.path = path;
            this.timestamp = Date.now();

            // Store for TOCTOU detection
            if (!fileOps[path]) {
                fileOps[path] = { checks: [], uses: [] };
            }
            fileOps[path].checks.push({
                time: this.timestamp,
                mode: mode,
                operation: 'access'
            });
        }
    });
}

// Track open() calls (use)
const open_ptr = Module.findExportByName(null, 'open');
if (open_ptr) {
    Interceptor.attach(open_ptr, {
        onEnter: function(args) {
            const path = Memory.readUtf8String(args[0]);
            const flags = args[1].toInt32();

            this.path = path;
            this.timestamp = Date.now();

            // Store for TOCTOU detection
            if (!fileOps[path]) {
                fileOps[path] = { checks: [], uses: [] };
            }
            fileOps[path].uses.push({
                time: this.timestamp,
                flags: flags,
                operation: 'open'
            });

            // Check for TOCTOU vulnerability
            if (fileOps[path].checks.length > 0) {
                const lastCheck = fileOps[path].checks[fileOps[path].checks.length - 1];
                const timeDiff = this.timestamp - lastCheck.time;

                if (timeDiff < 1000 && timeDiff > 0) { // Within 1 second
                    sendFinding(
                        'Potential TOCTOU Vulnerability',
                        'error',
                        {
                            file: path,
                            check_time: lastCheck.time,
                            use_time: this.timestamp,
                            time_window_ms: timeDiff,
                            risk: 'Race condition between check (access) and use (open)'
                        }
                    );
                }
            }
        }
    });
}

// Track readlink() - Symlink resolution
const readlink_ptr = Module.findExportByName(null, 'readlink');
if (readlink_ptr) {
    Interceptor.attach(readlink_ptr, {
        onEnter: function(args) {
            this.path = Memory.readUtf8String(args[0]);
            this.buf = args[1];
        },
        onLeave: function(retval) {
            if (retval.toInt32() > 0) {
                const target = Memory.readUtf8String(this.buf);
                log(`Symlink: ${this.path} -> ${target}`, 'warning');
                sendFinding(
                    'Symlink Resolution',
                    'info',
                    {
                        symlink: this.path,
                        target: target,
                        risk: 'Potential symlink race or traversal'
                    }
                );
            }
        }
    });
}

// ============================================================================
// 4. ENVIRONMENT VARIABLES
// ============================================================================

log('Analyzing environment variables...', 'info');

const getenv = Module.findExportByName(null, 'getenv');
if (getenv) {
    Interceptor.attach(getenv, {
        onEnter: function(args) {
            this.varname = Memory.readUtf8String(args[0]);
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                const value = Memory.readUtf8String(retval);

                // Check for dangerous env vars
                const dangerousVars = [
                    'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PATH',
                    'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH'
                ];

                if (dangerousVars.includes(this.varname)) {
                    sendFinding(
                        'Dangerous Environment Variable Access',
                        'warning',
                        {
                            variable: this.varname,
                            value: value,
                            risk: 'Library injection or PATH hijacking possible'
                        }
                    );
                }

                log(`getenv("${this.varname}") = "${value}"`, 'info');
            }
        }
    });
}

// Check LD_PRELOAD at startup
const ldPreload = Module.findExportByName(null, 'getenv');
if (ldPreload) {
    const envPtr = Module.findExportByName(null, 'getenv').call(null, Memory.allocUtf8String('LD_PRELOAD'));
    if (envPtr && !envPtr.isNull()) {
        const value = Memory.readUtf8String(envPtr);
        sendFinding(
            'LD_PRELOAD Detected',
            'error',
            {
                value: value,
                risk: 'Library injection attack vector - arbitrary code execution possible'
            }
        );
    }
}

// ============================================================================
// 5. SUID/SGID DETECTION
// ============================================================================

log('Checking for SUID/SGID binaries...', 'info');

// Check if current process is SUID/SGID
const getuid = Module.findExportByName(null, 'getuid');
const geteuid = Module.findExportByName(null, 'geteuid');
const getgid = Module.findExportByName(null, 'getgid');
const getegid = Module.findExportByName(null, 'getegid');

if (getuid && geteuid) {
    const uid = new NativeFunction(getuid, 'int', [])();
    const euid = new NativeFunction(geteuid, 'int', [])();

    if (uid !== euid) {
        sendFinding(
            'SUID Binary Detected',
            'error',
            {
                real_uid: uid,
                effective_uid: euid,
                risk: 'Privilege escalation possible - all vulnerabilities are critical'
            }
        );
    }
}

// Hook setuid() calls
const setuid = Module.findExportByName(null, 'setuid');
if (setuid) {
    Interceptor.attach(setuid, {
        onEnter: function(args) {
            const uid = args[0].toInt32();
            log(`setuid(${uid}) called`, 'error');
            sendFinding(
                'UID Manipulation',
                'error',
                {
                    target_uid: uid,
                    risk: 'Privilege escalation or privilege dropping'
                }
            );
        }
    });
}

// ============================================================================
// 6. FILE DESCRIPTOR ENUMERATION
// ============================================================================

log('Enumerating file descriptors...', 'info');

// Hook open to track FDs
const openFDs = new Map();
if (open_ptr) {
    Interceptor.attach(open_ptr, {
        onLeave: function(retval) {
            const fd = retval.toInt32();
            if (fd >= 0) {
                openFDs.set(fd, {
                    path: this.path,
                    flags: this.flags,
                    timestamp: Date.now()
                });
            }
        }
    });
}

// Hook socket() for network FDs
const socket_ptr = Module.findExportByName(null, 'socket');
if (socket_ptr) {
    Interceptor.attach(socket_ptr, {
        onEnter: function(args) {
            this.domain = args[0].toInt32();
            this.type = args[1].toInt32();
        },
        onLeave: function(retval) {
            const fd = retval.toInt32();
            if (fd >= 0) {
                sendFinding(
                    'Network Socket Created',
                    'info',
                    {
                        fd: fd,
                        domain: this.domain,
                        type: this.type
                    }
                );
            }
        }
    });
}

// ============================================================================
// 7. SYSCALL MONITORING
// ============================================================================

log('Setting up syscall monitoring...', 'info');

// Hook execve() - Process execution
const execve = Module.findExportByName(null, 'execve');
if (execve) {
    Interceptor.attach(execve, {
        onEnter: function(args) {
            const path = Memory.readUtf8String(args[0]);
            const argv = [];

            // Read argv array
            let i = 0;
            let argPtr = Memory.readPointer(args[1].add(i * Process.pointerSize));
            while (!argPtr.isNull()) {
                argv.push(Memory.readUtf8String(argPtr));
                i++;
                argPtr = Memory.readPointer(args[1].add(i * Process.pointerSize));
            }

            sendFinding(
                'Process Execution',
                'error',
                {
                    executable: path,
                    arguments: argv,
                    risk: 'Command injection or privilege escalation possible'
                }
            );
        }
    });
}

// ============================================================================
// 8. IPC MECHANISMS
// ============================================================================

log('Monitoring IPC mechanisms...', 'info');

// Shared memory
const shmget = Module.findExportByName(null, 'shmget');
if (shmget) {
    Interceptor.attach(shmget, {
        onEnter: function(args) {
            this.key = args[0].toInt32();
            this.size = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== -1) {
                sendFinding(
                    'Shared Memory Created',
                    'warning',
                    {
                        key: this.key,
                        size: this.size,
                        shmid: retval.toInt32(),
                        risk: 'IPC data leakage or race conditions'
                    }
                );
            }
        }
    });
}

// ============================================================================
// 9. DEPENDENCY CHAIN ANALYSIS
// ============================================================================

log('Analyzing dependency chain...', 'info');

const dependencyTree = {};

Process.enumerateModules().forEach(function(module) {
    try {
        const exports = module.enumerateExports();
        const imports = module.enumerateImports();

        dependencyTree[module.name] = {
            path: module.path,
            exports: exports.length,
            imports: imports.length,
            imported_from: []
        };

        // Track what this module imports from where
        imports.forEach(function(imp) {
            if (imp.module) {
                dependencyTree[module.name].imported_from.push({
                    symbol: imp.name,
                    module: imp.module
                });
            }
        });

    } catch (e) {
        log(`Error analyzing ${module.name}: ${e}`, 'warning');
    }
});

send({ type: 'dependency_tree', data: dependencyTree });

// ============================================================================
// SUMMARY
// ============================================================================

setTimeout(function() {
    log('Binary environment analysis complete', 'info');

    send({
        type: 'summary',
        data: {
            loaded_libraries: loadedLibraries.length,
            file_operations: Object.keys(fileOps).length,
            open_fds: openFDs.size,
            dependency_tree_size: Object.keys(dependencyTree).length
        }
    });
}, 1000);

log('Binary environment hooks installed', 'info');
