/*
 * raptor-gidmap-allow — write /proc/PID/gid_map WITHOUT denying setgroups.
 *
 * Drop-in replacement for newgidmap that skips the
 * /proc/PID/setgroups=deny write.  Requires CAP_SETGID via:
 *
 *     sudo setcap cap_setgid=ep raptor-gidmap-allow
 *
 * Without CAP_SETGID the kernel rejects the gid_map write (EPERM)
 * because /proc/PID/setgroups is still "allow".
 *
 * WHY: newgidmap (from shadow-utils) unconditionally writes "deny"
 * to /proc/PID/setgroups before writing gid_map.  This is a security
 * hardening choice — it prevents setgroups(2) inside the namespace.
 * But targets that call setgroups() during init (sudo, su, login,
 * etc.) abort before reaching their vulnerable code path.  This
 * helper leaves setgroups at "allow" so those targets can initialise.
 *
 * SECURITY: the only privilege this binary exercises is CAP_SETGID
 * (to write gid_map without deny).  No other capabilities are
 * requested.  The binary does NOT set any UIDs/GIDs itself — it
 * only writes the mapping file for a child process in a user
 * namespace the caller already owns.
 *
 * Usage: raptor-gidmap-allow PID inside_gid host_gid count [...]
 *        (same positional-arg format as newgidmap)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 5 || (argc - 2) % 3 != 0) {
        fprintf(stderr,
                "Usage: %s PID inside_gid host_gid count "
                "[inside_gid host_gid count ...]\n",
                argv[0]);
        return 1;
    }

    char path[64];
    snprintf(path, sizeof path, "/proc/%s/gid_map", argv[1]);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "%s: fopen(%s): %s\n",
                argv[0], path, strerror(errno));
        return 1;
    }

    for (int i = 2; i < argc; i += 3) {
        if (fprintf(f, "%s %s %s\n", argv[i], argv[i + 1], argv[i + 2]) < 0) {
            fprintf(stderr, "%s: write to %s: %s\n",
                    argv[0], path, strerror(errno));
            fclose(f);
            return 1;
        }
    }

    if (fclose(f) != 0) {
        fprintf(stderr, "%s: fclose(%s): %s\n",
                argv[0], path, strerror(errno));
        return 1;
    }

    return 0;
}
