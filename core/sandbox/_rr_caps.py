"""Discard setup capabilities before rr inspects its counter permissions."""
import ctypes
import os


class _Header(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]


class _Data(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ('effective', 'permitted', 'inheritable')]


def make_capability_drop(libc):
    # Resolve and allocate before fork. The namespace setup needs capabilities,
    # but rr must not mistake user-namespace CAP_SYS_ADMIN/CAP_PERFMON for host
    # authority to count kernel context switches (rr ContextSwitchEvent.cc).
    libc.capget.argtypes = [ctypes.POINTER(_Header), ctypes.POINTER(_Data)]
    libc.capget.restype = ctypes.c_int
    libc.capset.argtypes = [ctypes.POINTER(_Header), ctypes.POINTER(_Data)]
    libc.capset.restype = ctypes.c_int
    header = _Header(0x20080522, 0)
    data = (_Data * 2)()
    empty = (_Data * 2)()

    def drop():
        def checked(result):
            if result < 0:
                os.write(2, b'sandbox: rr capability drop failed; refusing execution\n')
                os._exit(126)
        checked(libc.capget(ctypes.byref(header), data))
        # Lock out root/setuid capability fixups while CAP_SETPCAP is still
        # present. For a non-root caller with no such capability, exec cannot
        # restore cleared sets; NO_NEW_PRIVS was already installed by seccomp.
        if data[0].effective & (1 << 8) or os.geteuid() == 0:
            bits = libc.prctl(27, 0, 0, 0, 0)  # PR_GET_SECUREBITS
            checked(bits)
            if bits & 0x0f != 0x0f:
                checked(libc.prctl(28, bits | 0x0f, 0, 0, 0))
        checked(libc.capset(ctypes.byref(header), empty))
        checked(libc.capget(ctypes.byref(header), data))
        if any(part.effective or part.permitted or part.inheritable for part in data):
            checked(-1)

    return drop
