/* raptor-coord-launcher — privileged bootstrap for the netns coordinator.
 *
 * Used by core/sandbox/netns_coordinator.py when an unprivileged
 * unshare(CLONE_NEWUSER|CLONE_NEWNET) is blocked by the host's LSM
 * (AppArmor's unprivileged_userns profile on Ubuntu 24.04+; SELinux policy
 * on hardened RHEL; or a sysctl pinning of kernel.unprivileged_userns_clone=0
 * on older Debian-family hosts).
 *
 * Threat model. The launcher performs a small, fixed privileged window:
 *   1. close inherited fds beyond 2  (defence-in-depth)
 *   2. unshare(CLONE_NEWUSER | CLONE_NEWNET)
 *   3. write /proc/self/uid_map ("0 EUID 1"), setgroups ("deny"), gid_map
 *   4. ioctl(SIOCSIFFLAGS, lo, IFF_UP | IFF_LOOPBACK | IFF_RUNNING)
 *   5. capset(empty)  -- drops every capability
 *   6. setenv(RAPTOR_COORD_FROM_LAUNCHER=1)  -- signal to coord.py
 *   7. execve(argv[1], &argv[1]) -- coordinator (Python interpreter + script)
 *
 * After step 5 the process has no caps in its parent userns; the only
 * residual privilege is "uid 0 inside the new user-namespace", which only
 * matters for operations on objects owned by that user-namespace (the
 * fresh netns and any user-namespace-scoped IPC the coordinator creates).
 * After step 7 the exec'd interpreter is bounded by AT_SECURE (set because
 * we had file caps, regardless of whether the operator used setcap or an
 * LSM grant) which strips LD_PRELOAD / LD_LIBRARY_PATH / etc.
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
 * launcher binary. Do not copy to /usr/local/bin or symlink.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    if (argc < 2) {
        fprintf(stderr,
                "raptor-coord-launcher: usage: %s <interpreter> "
                "[coord.py [args...]]\n"
                "  Launched by core/sandbox/netns_coordinator.py.\n"
                "  Not intended for direct invocation.\n",
                argv[0]);
        return 2;
    }

    close_inherited_fds();

    /* Capture parent-userns euid/egid BEFORE unshare. See write_id_maps()
     * docstring. */
    uid_t parent_uid = geteuid();
    gid_t parent_gid = getegid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        return log_errno(
            "unshare(NEWUSER|NEWNET) — host's LSM is blocking userns "
            "creation by this binary. On Ubuntu install the apparmor "
            "profile (raptor-coord-launcher.apparmor); on other distros "
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
    if (bring_lo_up() != 0) {
        return log_errno("bring_lo_up — loopback ifup failed in new netns");
    }
    if (drop_all_capabilities() != 0) {
        return log_errno("capset(empty) — failed to drop caps before exec");
    }

    /* Signal to the coordinator that its namespaces are already set up
     * and it must NOT re-do the unshare. */
    setenv("RAPTOR_COORD_FROM_LAUNCHER", "1", 1);

    /* execve. AT_SECURE will be set (we had file caps) which strips
     * LD_PRELOAD/LD_LIBRARY_PATH — fine for Python. */
    execv(argv[1], &argv[1]);
    /* Show which interpreter we failed to exec — operator's first
     * question is "which path did you actually try?" and the bare
     * "execv: <strerror>" wasn't enough to answer that. */
    fprintf(stderr, "raptor-coord-launcher: execv %s: %s\n",
            argv[1], strerror(errno));
    return 1;
}
