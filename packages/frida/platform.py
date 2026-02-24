#!/usr/bin/env python3
"""
RAPTOR Cross-Platform Frida Support

Platform detection and library mappings for:
- Linux (glibc, musl)
- macOS / iOS (Darwin)
- Windows
- Android (Bionic)
"""

from typing import Dict, List
from enum import Enum


class Platform(Enum):
    LINUX = "linux"
    MACOS = "macos"
    IOS = "ios"
    WINDOWS = "windows"
    ANDROID = "android"
    UNKNOWN = "unknown"


# Platform-specific system libraries
PLATFORM_LIBRARIES = {
    Platform.LINUX: [
        "libc.so.6",
        "libpthread.so.0",
        "libdl.so.2",
        "libm.so.6",
        "libssl.so",
        "libcrypto.so",
    ],
    Platform.MACOS: [
        "libsystem_kernel.dylib",
        "libsystem_c.dylib",
        "libsystem_malloc.dylib",
        "libsystem_pthread.dylib",
        "libSystem.B.dylib",
        "Security",
        "CoreFoundation",
    ],
    Platform.IOS: [
        "libsystem_kernel.dylib",
        "libsystem_c.dylib",
        "libsystem_malloc.dylib",
        "libSystem.B.dylib",
        "Security",
        "Foundation",
    ],
    Platform.WINDOWS: [
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "ws2_32.dll",
        "msvcrt.dll",
        "ucrtbase.dll",
        "crypt32.dll",
        "advapi32.dll",
    ],
    Platform.ANDROID: [
        "libc.so",
        "libdl.so",
        "liblog.so",
        "libssl.so",
        "libcrypto.so",
        "libbinder.so",
    ],
}

# Function name mappings across platforms
# Maps generic function name to platform-specific alternatives
FUNCTION_ALIASES = {
    # Memory allocation
    "malloc": {
        Platform.WINDOWS: ["HeapAlloc", "RtlAllocateHeap", "malloc"],
        "default": ["malloc"],
    },
    "free": {
        Platform.WINDOWS: ["HeapFree", "RtlFreeHeap", "free"],
        "default": ["free"],
    },

    # Network
    "connect": {
        Platform.WINDOWS: ["connect", "WSAConnect"],
        "default": ["connect"],
    },
    "send": {
        Platform.WINDOWS: ["send", "WSASend"],
        "default": ["send"],
    },
    "recv": {
        Platform.WINDOWS: ["recv", "WSARecv"],
        "default": ["recv"],
    },

    # File I/O
    "open": {
        Platform.WINDOWS: ["CreateFileW", "CreateFileA", "NtCreateFile"],
        Platform.ANDROID: ["open", "__open_2"],
        "default": ["open"],
    },
    "read": {
        Platform.WINDOWS: ["ReadFile", "NtReadFile"],
        "default": ["read"],
    },
    "write": {
        Platform.WINDOWS: ["WriteFile", "NtWriteFile"],
        "default": ["write"],
    },

    # Process
    "system": {
        Platform.WINDOWS: ["system", "CreateProcessW", "CreateProcessA"],
        "default": ["system"],
    },
    "exec": {
        Platform.WINDOWS: ["CreateProcessW", "CreateProcessA"],
        "default": ["execve", "execv", "execl"],
    },

    # Crypto
    "SSL_write": {
        Platform.WINDOWS: ["SSL_write", "EncryptMessage"],
        Platform.IOS: ["SSL_write", "SSLWrite"],
        Platform.ANDROID: ["SSL_write"],
        "default": ["SSL_write"],
    },
    "SSL_read": {
        Platform.WINDOWS: ["SSL_read", "DecryptMessage"],
        Platform.IOS: ["SSL_read", "SSLRead"],
        Platform.ANDROID: ["SSL_read"],
        "default": ["SSL_read"],
    },
}


def get_frida_platform_detection_js() -> str:
    """
    Generate JavaScript code for Frida to detect platform at runtime.
    """
    return """
// Platform detection
var PLATFORM = (function() {
    var p = Process.platform;
    if (p === 'darwin') {
        // Distinguish macOS from iOS
        try {
            Module.findBaseAddress('UIKit');
            return 'ios';
        } catch(e) {
            return 'macos';
        }
    }
    if (p === 'linux') {
        // Distinguish Linux from Android
        try {
            Module.findBaseAddress('libandroid_runtime.so');
            return 'android';
        } catch(e) {
            return 'linux';
        }
    }
    if (p === 'windows') return 'windows';
    return 'unknown';
})();

log('Platform detected: ' + PLATFORM, 'info');
"""


def get_cross_platform_find_symbol_js() -> str:
    """
    Generate JavaScript code for cross-platform symbol resolution.
    """
    return """
// Cross-platform library list
var PLATFORM_LIBS = {
    'linux': ['libc.so.6', 'libpthread.so.0', 'libdl.so.2', 'libssl.so', 'libcrypto.so'],
    'macos': ['libsystem_kernel.dylib', 'libsystem_c.dylib', 'libsystem_malloc.dylib', 'libSystem.B.dylib'],
    'ios': ['libsystem_kernel.dylib', 'libsystem_c.dylib', 'libSystem.B.dylib', 'Security'],
    'windows': ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'ws2_32.dll', 'msvcrt.dll', 'ucrtbase.dll'],
    'android': ['libc.so', 'libdl.so', 'libssl.so', 'libcrypto.so']
};

// Get export from specific module
function getExport(modName, funcName) {
    try {
        return Process.getModuleByName(modName).getExportByName(funcName);
    } catch(e) { return null; }
}

// Cross-platform symbol finder
function findSymbol(name, preferredModule) {
    // Try preferred module first
    if (preferredModule) {
        var ptr = getExport(preferredModule, name);
        if (ptr) return ptr;
    }

    // Try Module.findExportByName (works on some platforms)
    try {
        var ptr = Module.findExportByName(null, name);
        if (ptr) return ptr;
    } catch(e) {}

    // Search platform-specific libraries
    var libs = PLATFORM_LIBS[PLATFORM] || [];
    for (var i = 0; i < libs.length; i++) {
        var ptr = getExport(libs[i], name);
        if (ptr) {
            log('Found ' + name + ' in ' + libs[i], 'debug');
            return ptr;
        }
    }

    // Fallback: enumerate all modules
    try {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            try {
                var ptr = mods[i].getExportByName(name);
                if (ptr) {
                    log('Found ' + name + ' in ' + mods[i].name, 'debug');
                    return ptr;
                }
            } catch(e) {}
        }
    } catch(e) {}

    return null;
}

// Platform-aware function aliases
var FUNC_ALIASES = {
    'windows': {
        'malloc': ['HeapAlloc', 'malloc'],
        'free': ['HeapFree', 'free'],
        'open': ['CreateFileW', 'CreateFileA'],
        'read': ['ReadFile'],
        'write': ['WriteFile'],
        'connect': ['connect', 'WSAConnect'],
        'send': ['send', 'WSASend'],
        'recv': ['recv', 'WSARecv']
    }
};

// Find function with platform aliases
function findFunction(name) {
    // Try direct name first
    var ptr = findSymbol(name, null);
    if (ptr) return ptr;

    // Try platform aliases
    var aliases = FUNC_ALIASES[PLATFORM];
    if (aliases && aliases[name]) {
        for (var i = 0; i < aliases[name].length; i++) {
            ptr = findSymbol(aliases[name][i], null);
            if (ptr) return ptr;
        }
    }

    return null;
}
"""


def get_full_platform_boilerplate_js() -> str:
    """
    Get complete cross-platform boilerplate for Frida scripts.
    """
    return get_frida_platform_detection_js() + "\n" + get_cross_platform_find_symbol_js()
