/* raptor-coord-launcher — privileged bootstrap for the netns coordinator.
 *
 * Used by core/sandbox/netns_coordinator.py when an unprivileged
 * unshare(CLONE_NEWUSER|CLONE_NEWNET) is blocked by the host's LSM
 * (AppArmor's unprivileged_userns profile on Ubuntu 24.04+; SELinux policy
 * on hardened RHEL; or a sysctl pinning of kernel.unprivileged_userns_clone=0
 * on older Debian-family hosts).
 *
 * Argument contract (enforced BEFORE the unshare — refusal exits 3 with
 * a stderr message naming the violated contract):
 *
 *   1. argc == 3, exactly [launcher, interpreter, script]. The only
 *      caller, core/sandbox/netns_coordinator.py, passes exactly
 *      [HELPER, sys.executable, __file__]; extra argv is refused.
 *   2. SCRIPT PIN: realpath(argv[2]) must equal
 *      realpath(dirname(readlink(/proc/self/exe)) + "/../netns_coordinator.py").
 *      Exact match, no allowlist — this launcher only ever executes its
 *      own checkout's coordinator script.
 *   3. INTERPRETER TRUSTED-PATH: realpath(argv[1]) must be a regular
 *      file owned by uid 0 (root) or by the launcher binary's own owner
 *      (the operator who granted the capability), and must not be
 *      writable by untrusted parties: other-write is always refused;
 *      group-write is refused UNLESS the file's group is the file
 *      OWNER's primary group (per /etc/passwd — NSS-free lookup,
 *      see owner_primary_gid). On
 *      user-private-group systems (the Debian/Ubuntu default, umask
 *      002) a file group-writable by the owner's own single-member
 *      group is equivalent to owner-writable — no trust weakening —
 *      while group-write by any SHARED group (st_gid differing from
 *      the owner's primary group) stays refused. The one accepted
 *      edge: an operator whose primary group is deliberately shared
 *      with other users has chosen that trust model system-wide, and
 *      this check honours it. The rule admits /usr/bin/python3 and any
 *      operator-owned venv python with zero configuration (including
 *      umask-002 checkouts), and refuses any other local user's binary
 *      (they cannot create files owned by root or the operator). The
 *      same ownership/mode check applies to the pinned script and to
 *      the launcher's own directory.
 *   4. INVOKER IDENTITY: the invoking real AND effective uid must both
 *      be the trusted owner uid (the launcher binary's own owner — the
 *      operator who granted the capability / LSM profile), or root.
 *      Root is unconditionally trusted, mirroring the ownership rule in
 *      check_trusted_path (a root-owned install means the intended
 *      invoker is root; root also gains nothing from the grant it does
 *      not already have). Without this check, ANY local user with
 *      traverse+execute access to the checkout could consume the
 *      userns/netns grant; with it, only the granting identity can.
 *
 * The validation functions live in standalone form (helpers_validate.h)
 * and are exercised without any capability grant by `make test`.
 *
 * Threat model. The launcher performs a small, fixed privileged window:
 *   1. close inherited fds beyond 2  (defence-in-depth)
 *   2. validate the argument contract above
 *   3. unshare(CLONE_NEWUSER | CLONE_NEWNET)
 *   4. write /proc/self/uid_map ("0 EUID 1"), setgroups ("deny"), gid_map
 *   5. ioctl(SIOCSIFFLAGS, lo, IFF_UP | IFF_LOOPBACK | IFF_RUNNING)
 *   6. capset(empty)  -- drops every capability
 *   7. clearenv() + fixed minimal environment: PATH=/usr/bin:/bin,
 *      LANG/LC_ALL=C, RAPTOR_DIR derived from the pinned script's
 *      canonical path (NEVER from the caller's environment — an
 *      inherited RAPTOR_DIR/PYTHONPATH would steer the interpreter's
 *      import path and void the script pin), plus the RAPTOR_COORD_*
 *      sentinels (FROM_LAUNCHER=1 signals coord.py to skip its own
 *      unshare)
 *   8. execv(interpreter, {interpreter, script}) -- both canonicalised
 *
 * After step 6 the process has no caps in its parent userns; the only
 * residual privilege is "uid 0 inside the new user-namespace", which only
 * matters for operations on objects owned by that user-namespace (the
 * fresh netns and any user-namespace-scoped IPC the coordinator creates).
 * After step 8 the exec'd interpreter starts from the fixed minimal
 * environment constructed in step 7 — the caller's LD_PRELOAD /
 * LD_LIBRARY_PATH / PYTHONPATH classes are gone by construction. In the
 * setcap and SELinux grant modes the interpreter's exec ALSO carries
 * AT_SECURE (file caps were present at OUR exec and secure-execution
 * state survives into what we exec only via the environment, which we
 * cleared anyway); in the AppArmor grant mode there are no file caps and
 * no AT_SECURE anywhere — the clearenv() is the load-bearing control.
 *
 * THE LAUNCHER'S OWN exec is the reason this binary is STATICALLY
 * linked (-static-pie, enforced by the Makefile): in the AppArmor grant
 * mode the profile attaches by path with no file capabilities, so
 * exec of the launcher does NOT set AT_SECURE and a dynamic loader
 * would honour the INVOKER's LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH —
 * running a local user's constructor inside the profiled process,
 * with the profile's userns+capability grant, BEFORE main() and the
 * invoker-identity gate ever execute. Static linking removes the
 * dynamic loader from the picture entirely: there is no pre-main
 * interpreter to honour those variables, so the LD_* injection class
 * dies by construction (a blocklist-scrub of loader variables cannot
 * run early enough — the loader runs before any launcher code).
 * Accepted trade-off: libc security updates no longer reach the
 * launcher via the shared library — rebuild (make) after libc
 * updates. `make check` flags a dynamically-linked (stale, pre-static)
 * launcher binary.
 *
 * Operator grant options (the launcher accepts any of these — pick the
 * one your distro's hardening mechanism uses):
 *
 *  - AppArmor (Ubuntu 24.04+): install the named profile at
 *    core/sandbox/helpers/raptor-coord-launcher.apparmor. Required when
 *    apparmor_restrict_unprivileged_userns=1 (the Ubuntu default).
 *
 *  - File capabilities (other distros): sudo setcap
 *    cap_net_admin,cap_sys_admin+ep <path>. Required where the host blocks
 *    unprivileged userns via a different mechanism (e.g. RHEL with custom
 *    policy, Debian with kernel.unprivileged_userns_clone=0).
 *
 *  - SELinux (RHEL hardened): a policy module template lives at
 *    core/sandbox/helpers/raptor-coord-launcher.selinux.te. Validate on
 *    your specific corporate policy.
 *
 *  - Nothing: works when the operator has set
 *    kernel.apparmor_restrict_unprivileged_userns=0 (Ubuntu) or the
 *    distro's equivalent. In that case the coordinator does the unshare
 *    directly without invoking this launcher at all.
 *
 * The launcher binary lives at core/sandbox/helpers/raptor-coord-launcher
 * and MUST NOT be moved. The lookup contract in netns_coordinator.py is
 * relative to its own location — each RAPTOR checkout uses its own
 * launcher binary. Do not copy to /usr/local/bin or symlink. The script
 * pin above depends on this layout: the coordinator script is resolved
 * relative to the launcher's own realpath.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pwd.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include "helpers_validate.h"


/* ------------------------------------------------------------------ */
/* Argument-contract validation (capability-free; see helpers_validate.h
 * — compiled into the `make test` harness as well as this binary).     */
/* ------------------------------------------------------------------ */

/* Owner's primary gid via fgetpwent(3) on /etc/passwd — deliberately
 * NOT getpwuid(3): this binary is statically linked (see the header
 * comment) and glibc's getpwuid dlopen()s NSS modules at runtime,
 * which a static binary cannot rely on (glibc emits a link-time
 * warning and the lookup silently fails on version-mismatched hosts).
 * fgetpwent parses the stream directly with no NSS involvement.
 * Owners not present in /etc/passwd (e.g. LDAP-only accounts) return
 * -1 and the caller stays fail-closed for group-writable files, with
 * a refusal message naming the condition. */
static int owner_primary_gid(uid_t uid, gid_t *gid_out) {
    FILE *f = fopen("/etc/passwd", "re");
    if (f == NULL) {
        return -1;
    }
    struct passwd *pw;
    int rc = -1;
    while ((pw = fgetpwent(f)) != NULL) {
        if (pw->pw_uid == uid) {
            *gid_out = pw->pw_gid;
            rc = 0;
            break;
        }
    }
    fclose(f);
    return rc;
}


int check_trusted_path(const char *path, uid_t trusted_uid, int expect_dir,
                       const char *what, char *err, size_t errsz) {
    struct stat st;
    if (stat(path, &st) != 0) {
        snprintf(err, errsz, "trusted-path: cannot stat %s %s: %s",
                 what, path, strerror(errno));
        return -1;
    }
    if (expect_dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) {
        snprintf(err, errsz, "trusted-path: %s %s is not a %s",
                 what, path, expect_dir ? "directory" : "regular file");
        return -1;
    }
    if (st.st_uid != 0 && st.st_uid != trusted_uid) {
        snprintf(err, errsz,
                 "trusted-path: %s %s is owned by uid %u — must be owned "
                 "by root or by the launcher binary's owner (uid %u)",
                 what, path, (unsigned)st.st_uid, (unsigned)trusted_uid);
        return -1;
    }
    if (st.st_mode & S_IWOTH) {
        snprintf(err, errsz,
                 "trusted-path: %s %s is other-writable "
                 "(mode %04o) — refusing",
                 what, path, (unsigned)(st.st_mode & 07777));
        return -1;
    }
    if (st.st_mode & S_IWGRP) {
        /* Group-write is acceptable only when the group IS the file
         * owner's primary group (user-private-group layout, umask 002):
         * that is equivalent to owner-write. Group-write by any shared
         * group — or by an owner unknown to /etc/passwd — stays
         * refused. NSS-free lookup: see owner_primary_gid. */
        gid_t owner_gid;
        if (owner_primary_gid(st.st_uid, &owner_gid) != 0
                || owner_gid != st.st_gid) {
            snprintf(err, errsz,
                     "trusted-path: %s %s is group-writable by a group "
                     "(gid %u) that is not the owner's primary group "
                     "per /etc/passwd (mode %04o) — refusing",
                     what, path, (unsigned)st.st_gid,
                     (unsigned)(st.st_mode & 07777));
            return -1;
        }
    }
    return 0;
}


int check_invoker_identity(uid_t invoker_uid, uid_t invoker_euid,
                           uid_t trusted_uid, char *err, size_t errsz) {
    /* Root is unconditionally trusted, mirroring check_trusted_path's
     * ownership rule: a root-owned install is meant to be invoked by
     * root, and root gains nothing from the grant anyway. */
    if (invoker_uid == 0 && invoker_euid == 0) {
        return 0;
    }
    if (invoker_uid != trusted_uid || invoker_euid != trusted_uid) {
        snprintf(err, errsz,
                 "invoker identity: invoked by uid %u (euid %u), but this "
                 "launcher's userns grant belongs to its owner (uid %u) — "
                 "only the granting identity (or root) may consume it",
                 (unsigned)invoker_uid, (unsigned)invoker_euid,
                 (unsigned)trusted_uid);
        return -1;
    }
    return 0;
}


int derive_raptor_dir(const char *script_real, char *out, size_t outsz,
                      char *err, size_t errsz) {
    /* The pinned coordinator script lives at a FIXED depth in the
     * checkout: <root>/core/sandbox/netns_coordinator.py. The import
     * root handed to the interpreter is derived from that canonical
     * path — never read from the caller's environment — so a direct
     * invoker cannot point the coordinator's sys.path at their own
     * module tree under the grant. */
    static const char suffix[] = "/core/sandbox/netns_coordinator.py";
    const size_t sufl = sizeof suffix - 1;
    size_t slen = strlen(script_real);
    if (script_real[0] != '/' || slen < sufl
            || strcmp(script_real + (slen - sufl), suffix) != 0) {
        snprintf(err, errsz,
                 "import-root derivation: canonical coordinator path %s "
                 "does not end in %s — cannot derive the checkout root",
                 script_real, suffix);
        return -1;
    }
    size_t rootlen = slen - sufl;
    if (rootlen == 0) {
        /* Checkout unpacked at the filesystem root. */
        if (outsz < 2) {
            snprintf(err, errsz, "import-root derivation: caller buffer "
                     "too small");
            return -1;
        }
        out[0] = '/';
        out[1] = '\0';
        return 0;
    }
    if (rootlen + 1 > outsz) {
        snprintf(err, errsz, "import-root derivation: checkout root "
                 "exceeds the caller buffer");
        return -1;
    }
    memcpy(out, script_real, rootlen);
    out[rootlen] = '\0';
    return 0;
}


int validate_exec_target(int argc, char **argv, const char *self_exe,
                         char *interp_out, size_t interp_cap,
                         char *script_out, size_t script_cap,
                         uid_t *trusted_uid_out,
                         char *err, size_t errsz) {
    if (argc != 3) {
        snprintf(err, errsz,
                 "argument contract: expected exactly "
                 "[launcher, interpreter, script] (argc==3), got argc=%d. "
                 "Launched by core/sandbox/netns_coordinator.py; not "
                 "intended for direct invocation",
                 argc);
        return -1;
    }

    /* Canonicalise our own binary; its owner is the trusted uid (the
     * operator who applied the capability / LSM grant). */
    char self_real[PATH_MAX];
    if (realpath(self_exe, self_real) == NULL) {
        snprintf(err, errsz, "trusted-path: cannot resolve launcher path "
                 "%s: %s", self_exe, strerror(errno));
        return -1;
    }
    struct stat self_st;
    if (stat(self_real, &self_st) != 0 || !S_ISREG(self_st.st_mode)) {
        snprintf(err, errsz, "trusted-path: launcher %s is not a "
                 "stat-able regular file", self_real);
        return -1;
    }
    uid_t trusted_uid = self_st.st_uid;

    /* The launcher's own directory must not be writable by others —
     * otherwise the pinned script path next to it could be swapped. */
    char dir[PATH_MAX];
    strncpy(dir, self_real, sizeof dir - 1);
    dir[sizeof dir - 1] = '\0';
    char *slash = strrchr(dir, '/');
    if (slash == NULL) {
        snprintf(err, errsz, "trusted-path: launcher path %s has no "
                 "directory component", self_real);
        return -1;
    }
    if (slash == dir) {
        slash[1] = '\0';   /* binary sits in "/" */
    } else {
        *slash = '\0';
    }
    if (check_trusted_path(dir, trusted_uid, 1, "launcher directory",
                           err, errsz) != 0) {
        return -1;
    }

    /* SCRIPT PIN: the only script this launcher executes is the
     * coordinator one directory above its own location. */
    char expected[PATH_MAX + 64];
    int n = snprintf(expected, sizeof expected,
                     "%s/../netns_coordinator.py", dir);
    if (n <= 0 || n >= (int)sizeof expected) {
        snprintf(err, errsz, "script pin: pinned path construction "
                 "overflowed");
        return -1;
    }
    char expected_real[PATH_MAX];
    if (realpath(expected, expected_real) == NULL) {
        snprintf(err, errsz, "script pin: cannot resolve the pinned "
                 "coordinator script %s: %s", expected, strerror(errno));
        return -1;
    }
    char script_real[PATH_MAX];
    if (realpath(argv[2], script_real) == NULL) {
        snprintf(err, errsz, "script pin: cannot resolve script argument "
                 "%s: %s", argv[2], strerror(errno));
        return -1;
    }
    if (strcmp(script_real, expected_real) != 0) {
        snprintf(err, errsz,
                 "script pin: refusing to execute %s — this launcher only "
                 "executes its own checkout's coordinator (%s)",
                 script_real, expected_real);
        return -1;
    }
    if (check_trusted_path(script_real, trusted_uid, 0,
                           "coordinator script", err, errsz) != 0) {
        return -1;
    }

    /* INTERPRETER TRUSTED-PATH. */
    char interp_real[PATH_MAX];
    if (realpath(argv[1], interp_real) == NULL) {
        snprintf(err, errsz, "interpreter trusted-path: cannot resolve "
                 "%s: %s", argv[1], strerror(errno));
        return -1;
    }
    if (check_trusted_path(interp_real, trusted_uid, 0, "interpreter",
                           err, errsz) != 0) {
        return -1;
    }

    if (strlen(interp_real) >= interp_cap || strlen(script_real) >= script_cap) {
        snprintf(err, errsz, "internal: resolved path exceeds caller "
                 "buffer");
        return -1;
    }
    strcpy(interp_out, interp_real);
    strcpy(script_out, script_real);
    if (trusted_uid_out != NULL) {
        *trusted_uid_out = trusted_uid;
    }
    return 0;
}


#ifndef RAPTOR_HELPERS_TEST

#include <linux/capability.h>
#include <net/if.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>


static int log_errno(const char *step) {
    /* stderr is captured by the coordinator process and surfaced to the
     * operator. Writes happen before exec, before drop, so this is safe. */
    fprintf(stderr, "raptor-coord-launcher: %s: %s\n", step, strerror(errno));
    return 1;
}


static void close_inherited_fds(void) {
    /* The coordinator never passes extra fds to the launcher. Close any
     * stragglers a buggy caller might have left open so a launcher-side
     * bug can't read or write through an inherited handle. */
#ifdef SYS_close_range
    if (syscall(SYS_close_range, (unsigned int)3, ~(unsigned int)0,
                (unsigned int)0) == 0) {
        return;
    }
    /* close_range missing (pre-5.9) or refused — fall through. */
#endif
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd <= 0 || max_fd > 65536) max_fd = 1024;
    for (long fd = 3; fd < max_fd; fd++) {
        (void)close((int)fd);
    }
}


static int write_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, content, strlen(content));
    int saved = errno;
    close(fd);
    errno = saved;
    return n < 0 ? -1 : 0;
}


/* Caller passes the PRE-unshare euid/egid: after unshare(CLONE_NEWUSER)
 * we're mapped to the overflow uid (65534) until uid_map is written, and
 * the single-line bypass rule in user_namespaces(7) wants "the effective
 * UID of the writing process in the PARENT user namespace" — i.e. our
 * pre-unshare euid, not the post-unshare overflow. */
static int write_id_maps(uid_t parent_uid, gid_t parent_gid) {
    char buf[64];

    int n = snprintf(buf, sizeof buf, "0 %u 1\n", (unsigned)parent_uid);
    if (n <= 0 || n >= (int)sizeof buf) return -1;
    if (write_file("/proc/self/uid_map", buf) != 0) return -1;

    /* setgroups must be denied before gid_map can use the single-line
     * bypass write (without CAP_SETGID). */
    if (write_file("/proc/self/setgroups", "deny\n") != 0) return -1;

    n = snprintf(buf, sizeof buf, "0 %u 1\n", (unsigned)parent_gid);
    if (n <= 0 || n >= (int)sizeof buf) return -1;
    if (write_file("/proc/self/gid_map", buf) != 0) return -1;
    return 0;
}


static int bring_lo_up(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq req;
    memset(&req, 0, sizeof req);
    strncpy(req.ifr_name, "lo", IFNAMSIZ - 1);
    req.ifr_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
    int rc = ioctl(s, 0x8914 /* SIOCSIFFLAGS */, &req);
    int saved = errno;
    close(s);
    errno = saved;
    /* Loopback up enables both 127.0.0.0/8 and ::1/128 — one ioctl
     * is enough; the flags are interface properties, not protocol
     * properties. */
    return rc;
}


static int drop_all_capabilities(void) {
    /* Raw capset(VERSION_3, all-zero) — clears effective/permitted/
     * inheritable across all capability bits. Bounding set isn't touched
     * but is irrelevant: with empty effective+permitted, file caps on the
     * exec target are the only path to caps in the parent userns, and
     * the coordinator (a Python script) has no file caps. */
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    memset(&hdr, 0, sizeof hdr);
    memset(data, 0, sizeof data);
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    return (int)syscall(SYS_capset, &hdr, data);
}


int main(int argc, char **argv) {
    close_inherited_fds();

    /* Enforce the argument contract (see header comment) BEFORE any
     * privileged operation. Refusals exit 3. */
    char self_exe[PATH_MAX];
    ssize_t linklen = readlink("/proc/self/exe", self_exe,
                               sizeof self_exe - 1);
    if (linklen <= 0 || linklen >= (ssize_t)(sizeof self_exe - 1)) {
        fprintf(stderr, "raptor-coord-launcher: cannot resolve "
                "/proc/self/exe — refusing to launch\n");
        return 3;
    }
    self_exe[linklen] = '\0';

    char interp[PATH_MAX];
    char script[PATH_MAX];
    char err[2 * PATH_MAX];
    uid_t trusted_uid = (uid_t)-1;
    if (validate_exec_target(argc, argv, self_exe,
                             interp, sizeof interp,
                             script, sizeof script,
                             &trusted_uid, err, sizeof err) != 0) {
        fprintf(stderr, "raptor-coord-launcher: refusing to launch: %s\n",
                err);
        return 3;
    }

    /* INVOKER IDENTITY (contract item 4): only the trusted owner (or
     * root) may consume the capability/LSM grant. Checked BEFORE the
     * unshare so a foreign local user with traverse+execute access to
     * the checkout gets a refusal, not a namespace. */
    if (check_invoker_identity(getuid(), geteuid(), trusted_uid,
                               err, sizeof err) != 0) {
        fprintf(stderr, "raptor-coord-launcher: refusing to launch: %s\n",
                err);
        return 3;
    }

    /* Derive the coordinator's Python import root from the pinned,
     * already-canonicalised script path, BEFORE any privileged step.
     * The inherited environment is discarded below; RAPTOR_DIR must
     * come from the validated checkout, never from the caller. */
    char raptor_dir[PATH_MAX];
    if (derive_raptor_dir(script, raptor_dir, sizeof raptor_dir,
                          err, sizeof err) != 0) {
        fprintf(stderr, "raptor-coord-launcher: refusing to launch: %s\n",
                err);
        return 3;
    }

    /* Capture parent-userns euid/egid BEFORE unshare. See write_id_maps()
     * docstring. */
    uid_t parent_uid = geteuid();
    gid_t parent_gid = getegid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        return log_errno(
            "unshare(NEWUSER|NEWNET) — host's LSM is blocking userns "
            "creation by this binary. On Ubuntu install the apparmor "
            "profile (make apparmor-profile, then install the rendered "
            "file); on other distros "
            "ensure setcap cap_net_admin,cap_sys_admin+ep is applied "
            "OR install the appropriate LSM grant from "
            "core/sandbox/helpers/");
    }
    if (write_id_maps(parent_uid, parent_gid) != 0) {
        return log_errno(
            "write_id_maps — typically blocked by an LSM "
            "(unprivileged_userns apparmor profile, SELinux confinement). "
            "Install the LSM grant from core/sandbox/helpers/");
    }
    /* Close the ptrace window for the rest of the privileged stretch
     * (lo-up through capset): on the AppArmor-only grant path this
     * process runs with capabilities but stays dumpable, so a
     * same-UID tracer could attach mid-window. This CANNOT cover the
     * unshare->idmap stretch: a non-dumpable process's /proc/self/
     * ownership flips to global root, and writing our own uid_map
     * would then fail EACCES — the map writes above are the last
     * thing that needs dumpable. execve of the (post-capset,
     * unprivileged) coordinator resets dumpable to 1, so no restore
     * is needed. */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        return log_errno("prctl(PR_SET_DUMPABLE, 0) — refusing to keep "
                         "the privileged window traceable");
    }

    if (bring_lo_up() != 0) {
        return log_errno("bring_lo_up — loopback ifup failed in new netns");
    }
    if (drop_all_capabilities() != 0) {
        return log_errno("capset(empty) — failed to drop caps before exec");
    }

    /* Discard the caller's environment wholesale and construct a fixed
     * minimal one. On a direct invocation the inherited environ is
     * attacker input: RAPTOR_DIR (which netns_coordinator.py inserts
     * into sys.path — hard lookup by repo doctrine, so the launcher
     * must be the one supplying a trustworthy value) and PYTHONPATH
     * both steer the interpreter's module resolution, which would run
     * caller-chosen Python under the grant and void the script pin.
     * AT_SECURE strips only the LD_ and glibc classes, not Python's
     * environment surface.
     *
     * RAPTOR_COORD_FROM_LAUNCHER=1 signals the coordinator that its
     * namespaces are already set up and it must NOT re-do the unshare;
     * RAPTOR_COORD_REEXEC_GUARD=1 keeps the coordinator's re-exec
     * loop-breaker armed now that the caller's copy is cleared. */
    if (clearenv() != 0
            || setenv("PATH", "/usr/bin:/bin", 1) != 0
            || setenv("LANG", "C", 1) != 0
            || setenv("LC_ALL", "C", 1) != 0
            || setenv("RAPTOR_DIR", raptor_dir, 1) != 0
            || setenv("RAPTOR_COORD_REEXEC_GUARD", "1", 1) != 0
            || setenv("RAPTOR_COORD_FROM_LAUNCHER", "1", 1) != 0) {
        return log_errno("clearenv/setenv — could not construct the "
                         "fixed coordinator environment");
    }

    /* execv the CANONICALISED interpreter+script from validation — not
     * the raw argv — so the validated paths are the executed paths.
     * The interpreter starts from the fixed environment built above:
     * clearenv() removed the caller's LD_ and PYTHONPATH classes, so no
     * AT_SECURE reliance is needed here (and none exists in the
     * AppArmor grant mode — no file caps; see the header comment). */
    char *exec_argv[] = { interp, script, NULL };
    execv(interp, exec_argv);
    /* Show which interpreter we failed to exec — operator's first
     * question is "which path did you actually try?" and the bare
     * "execv: <strerror>" wasn't enough to answer that. */
    fprintf(stderr, "raptor-coord-launcher: execv %s: %s\n",
            interp, strerror(errno));
    return 1;
}

#endif /* RAPTOR_HELPERS_TEST */
