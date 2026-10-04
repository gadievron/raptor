/*
 * setgroups(2) stub for user-namespace sandboxes.
 *
 * User namespaces deny setgroups(2) via /proc/self/setgroups=deny
 * (written by newgidmap during namespace setup).  Targets that call
 * setgroups() during initialisation (e.g. sudo, su, login) abort
 * before reaching their vulnerable code path.
 *
 * This stub returns 0 (success) without making the syscall.  It
 * grants no real capability — no GIDs are mapped in the namespace,
 * so setgroups has nothing to set.  The stub just prevents the
 * EPERM-triggered abort.
 *
 * Injected via LD_PRELOAD by the exploit-engine substrate.
 * Ineffective for real setuid binaries (ld.so strips LD_PRELOAD
 * when AT_SECURE is set); fine for compiled corpus reproducers.
 */
#include <sys/types.h>
#include <unistd.h>

int setgroups(size_t size, const gid_t *list) {
    (void)size;
    (void)list;
    return 0;
}
