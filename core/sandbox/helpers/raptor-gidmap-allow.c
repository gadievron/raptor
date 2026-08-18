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
 * (to write gid_map without deny).  Skipping newgidmap means also
 * skipping newgidmap's /etc/subgid and namespace checks, so this
 * binary enforces its own contract before touching gid_map
 * (refusal exits 3 with a stderr message naming the violated rule):
 *
 *   1. NAMESPACE OWNERSHIP: the user namespace of the target PID must
 *      be owned by the invoker's real uid (NS_GET_OWNER_UID on
 *      /proc/PID/ns/user).  File caps do not change real ids, so this
 *      confines the write to namespaces the caller itself created —
 *      another user's namespace, or the init namespace, is refused.
 *   2. GID CONFINEMENT: every host gid covered by the mapping triples
 *      must be the invoker's real/effective gid or one of its
 *      supplementary groups (getgroups).  The caller can only map
 *      gids it already holds — no subgid delegation, no privilege
 *      widening.
 *   3. ARGUMENT HYGIENE: the PID and every triple component must be
 *      strictly numeric decimal; at most 8 triples; counts must be
 *      positive, bounded, and must not overflow the gid range.
 *
 *  The binary does NOT set any UIDs/GIDs itself — it only writes the
 *  mapping file for a child process in a user namespace the caller
 *  already owns.  The validation lives in standalone functions
 *  (helpers_validate.h) exercised without any capability grant by
 *  `make test`.
 *
 * Usage: raptor-gidmap-allow PID inside_gid host_gid count [...]
 *        (same positional-arg format as newgidmap)
 *
 * The only RAPTOR call site is core/sandbox/_spawn.py, which passes
 * exactly one triple — "0 <invoker's own gid> 1" — for a namespace the
 * invoker just created.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>

#if defined(__has_include)
# if __has_include(<linux/nsfs.h>)
#  include <linux/nsfs.h>
# endif
#endif
#ifndef NS_GET_OWNER_UID
/* From <linux/nsfs.h> (kernel >= 4.11, guaranteed on supported hosts):
 * returns the owner uid of a user namespace fd. */
# define NS_GET_OWNER_UID _IO(0xb7, 0x4)
#endif

#include "helpers_validate.h"


/* ------------------------------------------------------------------ */
/* Argument-contract validation (capability-free; see helpers_validate.h
 * — compiled into the `make test` harness as well as this binary).     */
/* ------------------------------------------------------------------ */

int parse_strict_ulong(const char *s, unsigned long *out) {
    /* First char must be a digit: rejects empty strings and the
     * leading whitespace / '+' / '-' that strtoul would accept. */
    if (s == NULL || s[0] < '0' || s[0] > '9') return -1;
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return -1;
    *out = v;
    return 0;
}


static int gid_in_set(unsigned long gid, const gid_t *allowed,
                      size_t n_allowed) {
    for (size_t i = 0; i < n_allowed; i++) {
        if ((unsigned long)allowed[i] == gid) return 1;
    }
    return 0;
}


int validate_mapping_args(int argc, char **argv,
                          const gid_t *allowed, size_t n_allowed,
                          unsigned long *pid_out,
                          char *err, size_t errsz) {
    if (argc < 5 || (argc - 2) % 3 != 0) {
        snprintf(err, errsz,
                 "argument hygiene: usage is PID inside_gid host_gid count "
                 "[inside_gid host_gid count ...] (got %d arguments)",
                 argc - 1);
        return -1;
    }
    size_t triples = (size_t)(argc - 2) / 3;
    if (triples > RAPTOR_GIDMAP_MAX_TRIPLES) {
        snprintf(err, errsz,
                 "argument hygiene: at most %d mapping triples accepted "
                 "(got %zu)", RAPTOR_GIDMAP_MAX_TRIPLES, triples);
        return -1;
    }

    unsigned long pid = 0;
    if (parse_strict_ulong(argv[1], &pid) != 0 || pid == 0
            || pid > 0x7fffffffUL) {
        snprintf(err, errsz,
                 "argument hygiene: PID '%s' is not a strictly numeric, "
                 "valid process id", argv[1]);
        return -1;
    }

    for (size_t t = 0; t < triples; t++) {
        const char *inside_s = argv[2 + 3 * t];
        const char *host_s = argv[3 + 3 * t];
        const char *count_s = argv[4 + 3 * t];
        unsigned long inside = 0, host = 0, count = 0;
        if (parse_strict_ulong(inside_s, &inside) != 0
                || parse_strict_ulong(host_s, &host) != 0
                || parse_strict_ulong(count_s, &count) != 0) {
            snprintf(err, errsz,
                     "argument hygiene: mapping triple %zu "
                     "('%s %s %s') is not strictly numeric",
                     t + 1, inside_s, host_s, count_s);
            return -1;
        }
        if (count == 0) {
            snprintf(err, errsz,
                     "argument hygiene: mapping triple %zu has count 0 "
                     "(count must be positive)", t + 1);
            return -1;
        }
        if (count > 65536) {
            snprintf(err, errsz,
                     "argument hygiene: mapping triple %zu count %lu "
                     "exceeds the 65536 bound", t + 1, count);
            return -1;
        }
        /* 0xFFFFFFFF is the kernel's invalid-gid sentinel; the mapped
         * range must stay strictly below it, without wrapping. */
        if (inside > 0xFFFFFFFEUL || host > 0xFFFFFFFEUL
                || host + count - 1 > 0xFFFFFFFEUL
                || inside + count - 1 > 0xFFFFFFFEUL) {
            snprintf(err, errsz,
                     "argument hygiene: mapping triple %zu exceeds the "
                     "valid gid range", t + 1);
            return -1;
        }
        for (unsigned long j = 0; j < count; j++) {
            if (!gid_in_set(host + j, allowed, n_allowed)) {
                snprintf(err, errsz,
                         "gid confinement: host gid %lu (triple %zu) is "
                         "not the invoker's real/effective gid or in its "
                         "supplementary groups", host + j, t + 1);
                return -1;
            }
        }
    }

    *pid_out = pid;
    return 0;
}


int check_ns_owner(unsigned long pid, uid_t expect_uid,
                   char *err, size_t errsz) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%lu/ns/user", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, errsz, "namespace ownership: cannot open %s: %s",
                 path, strerror(errno));
        return -1;
    }
    uid_t owner = (uid_t)-1;
    int rc = ioctl(fd, NS_GET_OWNER_UID, &owner);
    int saved = errno;
    close(fd);
    if (rc != 0) {
        snprintf(err, errsz,
                 "namespace ownership: NS_GET_OWNER_UID on %s: %s",
                 path, strerror(saved));
        return -1;
    }
    if (owner != expect_uid) {
        snprintf(err, errsz,
                 "namespace ownership: user namespace of pid %lu is owned "
                 "by uid %u, not the invoking uid %u — refusing to write "
                 "its gid_map", pid, (unsigned)owner, (unsigned)expect_uid);
        return -1;
    }
    return 0;
}


#ifndef RAPTOR_HELPERS_TEST

/* Gather the gids the invoker genuinely holds: real gid, effective gid,
 * and the supplementary groups. File caps change none of these. */
static int collect_invoker_gids(gid_t **out, size_t *n_out) {
    int ng = getgroups(0, NULL);
    if (ng < 0) ng = 0;
    gid_t *buf = calloc((size_t)ng + 2, sizeof *buf);
    if (buf == NULL) return -1;
    buf[0] = getgid();
    buf[1] = getegid();
    int got = 0;
    if (ng > 0) {
        got = getgroups(ng, buf + 2);
        if (got < 0) got = 0;
    }
    *out = buf;
    *n_out = (size_t)got + 2;
    return 0;
}


int main(int argc, char **argv) {
    char err[512];

    gid_t *allowed = NULL;
    size_t n_allowed = 0;
    if (collect_invoker_gids(&allowed, &n_allowed) != 0) {
        fprintf(stderr, "%s: cannot enumerate invoker gids: %s\n",
                argv[0], strerror(errno));
        return 3;
    }

    unsigned long pid = 0;
    if (validate_mapping_args(argc, argv, allowed, n_allowed, &pid,
                              err, sizeof err) != 0) {
        fprintf(stderr, "%s: refusing: %s\n", argv[0], err);
        free(allowed);
        return 3;
    }
    free(allowed);

    if (check_ns_owner(pid, getuid(), err, sizeof err) != 0) {
        fprintf(stderr, "%s: refusing: %s\n", argv[0], err);
        return 3;
    }

    char path[64];
    snprintf(path, sizeof path, "/proc/%lu/gid_map", pid);

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

#endif /* RAPTOR_HELPERS_TEST */
