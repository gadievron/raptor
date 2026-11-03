"""Standalone sandboxed ELF reader; imports no RAPTOR application modules."""
import contextlib
import json
import os
import resource
import stat
import sys


class _DescriptorInput(int):
    """open() consumes the descriptor; os.fspath() supplies only a display name.

    Pwntools opens its argument and separately normalises it for self.path.
    Python's file API accepts this integer directly, while the path protocol
    supplies a harmless label. No /dev/fd or /proc alias needs a read grant.
    """

    def __fspath__(self):
        return 'input.elf'


def _limit(resource_id, value):
    _, hard = resource.getrlimit(resource_id)
    if hard != resource.RLIM_INFINITY:
        value = min(value, hard)
    resource.setrlimit(resource_id, (value, value))


def _collect(path, user_site, max_input):
    # Linux enforces AS; macOS accepts it without a hard memory guarantee.
    # Failure to install the limits refuses parsing, rather than silently
    # trusting the sandbox backend's best-effort setrlimit warning.
    _limit(resource.RLIMIT_AS, 2048 * 1024 * 1024)
    _limit(resource.RLIMIT_CPU, 10)
    if user_site:
        import site
        site.addsitedir(user_site)  # installed user hooks run only after confinement
    from pwnlib.context import context
    from pwnlib.elf.elf import ELF
    context.log_level = 'error'
    # Imports may need loader helper processes. Parsing these bytes does not;
    # prevent a compromised parser from multiplying per-process budgets.
    _limit(resource.RLIMIT_NPROC, 0)
    # Mitigation facts need imported names, not PLT addresses. Pwntools'
    # PLT population invokes Unicorn and reserves huge guest mappings; a
    # finite AS cap otherwise silently drops PLT entries and FORTIFY. This
    # process serves one request, so the override cannot affect callers.
    if not callable(getattr(ELF, '_populate_plt', None)):
        raise RuntimeError('unsupported pwntools PLT discovery API')
    ELF._populate_plt = lambda self: None
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_input:
            raise ValueError('input is not a budgeted regular file')
        # Parse the validated inode, not a pathname the target can replace.
        # ELF owns and closes its duplicate; keep our validation fd separate.
        # A constructor failure terminates this one-shot worker.
        elf = ELF(_DescriptorInput(os.dup(descriptor)), checksec=False)
        # checksec's FORTIFY flag tests imported *_chk function names in
        # elf.plt. Reconstruct names only: data symbols ending in _chk must
        # not mint FORTIFY, and no PLT addresses or emulation are needed.
        dynamic = elf.get_section_by_name('.dynsym')
        if dynamic is not None:
            imports = {
                symbol.name for symbol in dynamic.iter_symbols()
                if symbol.entry.st_shndx == 'SHN_UNDEF'
                and symbol.entry.st_info.type in ('STT_FUNC', 'STT_GNU_IFUNC')
            }
            elf.plt.update(dict.fromkeys(imports.intersection(elf.got), 0))
        os_abi = str(elf.header.get('e_ident', {}).get('EI_OSABI', ''))
        facts = dict(
            arch=elf.arch, bits=elf.bits, endian=elf.endian,
            os_abi=os_abi.replace('ELFOSABI_', '').replace('_', ' '),
            relro=elf.relro, pie=elf.pie, nx=elf.nx, canary=elf.canary,
            fortify=elf.fortify,
            has_gnu_stack=any(segment.header.p_type == 'PT_GNU_STACK' for segment in elf.segments),
            checksec=elf.checksec(banner=False, color=False),
        )
        elf.close()
        if len(facts['checksec']) > 16 * 1024:
            raise ValueError('checksec result exceeds record budget')
        return facts
    finally:
        os.close(descriptor)


def main():
    try:
        # Dependency logs must not become records in the result channel.
        with contextlib.redirect_stdout(sys.stderr):
            facts = _collect(sys.argv[1], sys.argv[2], int(sys.argv[3]))
        payload = json.dumps(facts, ensure_ascii=True, allow_nan=False).encode('ascii')
        if len(payload) > 128 * 1024:
            return 1
        sys.stdout.buffer.write(payload)
        return 0
    except Exception as exc:
        # Parent logging bounds and escapes stderr; never serialize exceptions.
        sys.stderr.write('ELF worker failed: ' + type(exc).__name__ + '\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
