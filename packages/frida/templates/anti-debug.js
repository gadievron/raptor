/**
 * RAPTOR Frida Template: Anti-Debugging Bypass
 *
 * Bypasses common anti-debugging techniques:
 * - ptrace detection
 * - Debugger checks
 * - Timing attacks
 * - Anti-tampering
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

log('Anti-debug bypass started', 'info');

// macOS/Linux: ptrace
const ptrace_ptr = Module.findExportByName(null, 'ptrace');
if (ptrace_ptr) {
    Interceptor.replace(ptrace_ptr, new NativeCallback(function(request, pid, addr, data) {
        log('ptrace() called - returning success', 'warning');
        sendFinding(
            'Anti-Debug Bypassed',
            'info',
            'ptrace() call intercepted and neutralized'
        );
        return 0; // Success
    }, 'int', ['int', 'int', 'pointer', 'pointer']));
}

// macOS: sysctl debugger detection
const sysctl_ptr = Module.findExportByName(null, 'sysctl');
if (sysctl_ptr) {
    Interceptor.attach(sysctl_ptr, {
        onEnter: function(args) {
            const name = Memory.readPointer(args[0]);
            const namelen = args[1].toInt32();

            // Check if querying for debugger (CTL_KERN, KERN_PROC, KERN_PROC_PID)
            if (namelen >= 4) {
                const mib = [];
                for (let i = 0; i < namelen; i++) {
                    mib.push(Memory.readInt(name.add(i * 4)));
                }

                // CTL_KERN=1, KERN_PROC=14
                if (mib[0] === 1 && mib[1] === 14) {
                    this.isDebugQuery = true;
                    this.oldinfo = args[2];
                }
            }
        },
        onLeave: function(retval) {
            if (this.isDebugQuery && !this.oldinfo.isNull()) {
                // Clear P_TRACED flag in kinfo_proc structure
                try {
                    const p_flag_offset = 32; // Offset of p_flag in kinfo_proc
                    const p_flag = Memory.readU32(this.oldinfo.add(p_flag_offset));
                    const P_TRACED = 0x00000800;
                    Memory.writeU32(this.oldinfo.add(p_flag_offset), p_flag & ~P_TRACED);
                    log('sysctl debugger check bypassed', 'warning');
                } catch (e) {}
            }
        }
    });
}

// iOS: Anti-jailbreak detection
if (ObjC.available) {
    // File existence checks
    const fileExistsAtPath = ObjC.classes.NSFileManager['- fileExistsAtPath:'];
    if (fileExistsAtPath) {
        Interceptor.attach(fileExistsAtPath.implementation, {
            onEnter: function(args) {
                const path = ObjC.Object(args[2]).toString();

                // Common jailbreak paths
                const jailbreakPaths = [
                    '/Applications/Cydia.app',
                    '/Library/MobileSubstrate',
                    '/bin/bash',
                    '/usr/sbin/sshd',
                    '/etc/apt',
                    '/private/var/lib/apt/'
                ];

                if (jailbreakPaths.some(jp => path.includes(jp))) {
                    this.spoofResult = true;
                }
            },
            onLeave: function(retval) {
                if (this.spoofResult) {
                    retval.replace(0); // Return NO
                    log('Jailbreak detection bypassed: file check', 'warning');
                }
            }
        });
    }

    // Fork detection
    const fork_ptr = Module.findExportByName(null, 'fork');
    if (fork_ptr) {
        Interceptor.replace(fork_ptr, new NativeCallback(function() {
            log('fork() blocked (anti-debug)', 'warning');
            return -1; // Fail
        }, 'int', []));
    }
}

// Android: Anti-debugging
if (Java.available) {
    Java.perform(function() {
        // Debug.isDebuggerConnected()
        try {
            const Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function() {
                log('Debug.isDebuggerConnected() bypassed', 'warning');
                return false;
            };
        } catch (e) {}

        // ApplicationInfo.FLAG_DEBUGGABLE check
        try {
            const ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
            ApplicationInfo.flags.value = ApplicationInfo.flags.value & ~0x2; // Clear FLAG_DEBUGGABLE
        } catch (e) {}

        // Root detection - RootBeer library
        try {
            const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
            RootBeer.isRooted.implementation = function() {
                log('RootBeer.isRooted() bypassed', 'warning');
                return false;
            };
        } catch (e) {}
    });
}

// Timing attack bypass - speed up time checks
const clock_gettime = Module.findExportByName(null, 'clock_gettime');
if (clock_gettime) {
    let lastTime = 0;
    Interceptor.attach(clock_gettime, {
        onLeave: function(retval) {
            // Make time appear consistent (no large gaps that indicate debugging)
            const timespec = this.context.r1 || this.context.rsi;
            if (timespec) {
                const tv_sec = Memory.readU64(timespec);
                const tv_nsec = Memory.readU64(timespec.add(8));

                if (lastTime > 0) {
                    const currentTime = tv_sec * 1000000000 + tv_nsec;
                    const elapsed = currentTime - lastTime;

                    // If more than 100ms elapsed (indicates breakpoint), fake it
                    if (elapsed > 100000000) {
                        Memory.writeU64(timespec.add(8), lastTime + 1000000); // Add 1ms
                        log('Timing attack bypassed', 'info');
                    }
                }

                lastTime = tv_sec * 1000000000 + tv_nsec;
            }
        }
    });
}

log('Anti-debug bypasses installed', 'info');
sendFinding(
    'Anti-Debug Active',
    'info',
    'All anti-debugging bypasses have been installed'
);
