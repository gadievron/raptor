/* helpers_test.c — unprivileged robustness harness for the sandbox
 * helpers' argument-contract validation.
 *
 * Built by `make test` with -DRAPTOR_HELPERS_TEST, which compiles the
 * two helper .c files WITHOUT their main() so the exact production
 * validation code links into this harness. No capability grant, no
 * root, no /etc configuration is needed: the trusted-path checks run
 * against temp files, and the namespace-ownership check runs against a
 * self-created user namespace (probed first; skipped gracefully when
 * the host blocks unprivileged userns).
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/wait.h>

#include "helpers_validate.h"

static int failures = 0;

#define CHECK(cond, name) do { \
        if (cond) { \
            printf("ok   %s\n", (name)); \
        } else { \
            printf("FAIL %s (%s:%d)\n", (name), __FILE__, __LINE__); \
            failures++; \
        } \
    } while (0)


static void write_file_mode(const char *path, const char *content,
                            mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        fprintf(stderr, "harness: open(%s): %s\n", path, strerror(errno));
        exit(1);
    }
    if (fchmod(fd, mode) != 0) {
        fprintf(stderr, "harness: fchmod(%s): %s\n", path, strerror(errno));
        close(fd);
        exit(1);
    }
    FILE *f = fdopen(fd, "w");
    if (f == NULL) {
        fprintf(stderr, "harness: fdopen(%s): %s\n", path, strerror(errno));
        close(fd);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}


/* ------------------------------------------------------------------ */
/* raptor-coord-launcher: validate_exec_target / check_trusted_path     */
/* ------------------------------------------------------------------ */

static void test_exec_target(void) {
    char base[] = "/tmp/raptor-helpers-test-XXXXXX";
    if (mkdtemp(base) == NULL) {
        fprintf(stderr, "harness: mkdtemp: %s\n", strerror(errno));
        exit(1);
    }
    char helpers[PATH_MAX], launcher[PATH_MAX], script[PATH_MAX];
    char interp[PATH_MAX], other[PATH_MAX];
    snprintf(helpers, sizeof helpers, "%s/helpers", base);
    snprintf(launcher, sizeof launcher, "%s/helpers/raptor-coord-launcher",
             base);
    snprintf(script, sizeof script, "%s/netns_coordinator.py", base);
    snprintf(interp, sizeof interp, "%s/python", base);
    snprintf(other, sizeof other, "%s/other.py", base);
    if (mkdir(helpers, 0755) != 0) {
        fprintf(stderr, "harness: mkdir(%s): %s\n", helpers,
                strerror(errno));
        exit(1);
    }
    write_file_mode(launcher, "#!/bin/false\n", 0755);
    write_file_mode(script, "print('coord')\n", 0644);
    write_file_mode(interp, "#!/bin/false\n", 0755);
    write_file_mode(other, "print('other')\n", 0644);

    char io[PATH_MAX], so[PATH_MAX], err[2 * PATH_MAX];
    char *argv_ok[] = { launcher, interp, script, NULL };

    CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                               so, sizeof so, NULL, err, sizeof err) == 0,
          "accepts the canonical [interpreter, script] shape");
    uid_t tuid = (uid_t)-1;
    CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                               so, sizeof so, &tuid, err, sizeof err) == 0
              && tuid == getuid(),
          "reports the launcher binary's owner as the trusted uid");
    char expect[PATH_MAX];
    CHECK(realpath(interp, expect) != NULL && strcmp(io, expect) == 0,
          "returns the canonicalised interpreter path");
    CHECK(realpath(script, expect) != NULL && strcmp(so, expect) == 0,
          "returns the canonicalised script path");

    CHECK(validate_exec_target(2, argv_ok, launcher, io, sizeof io,
                               so, sizeof so, NULL, err, sizeof err) != 0,
          "refuses argc=2 (missing script)");
    char *argv_extra[] = { launcher, interp, script, script, NULL };
    CHECK(validate_exec_target(4, argv_extra, launcher, io, sizeof io,
                               so, sizeof so, NULL, err, sizeof err) != 0
              && strstr(err, "argument contract") != NULL,
          "refuses extra argv beyond [interpreter, script]");

    char *argv_other[] = { launcher, interp, other, NULL };
    CHECK(validate_exec_target(3, argv_other, launcher, io, sizeof io,
                               so, sizeof so, NULL, err, sizeof err) != 0
              && strstr(err, "script pin") != NULL,
          "script pin refuses a co-located but different script");

    char missing[PATH_MAX];
    snprintf(missing, sizeof missing, "%s/nonexistent", base);
    char *argv_missing[] = { launcher, missing, script, NULL };
    CHECK(validate_exec_target(3, argv_missing, launcher, io, sizeof io,
                               so, sizeof so, NULL, err, sizeof err) != 0,
          "refuses a nonexistent interpreter");

    chmod(interp, 0777);
    CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                               so, sizeof so, NULL, err, sizeof err) != 0
              && strstr(err, "interpreter") != NULL,
          "refuses an other-writable interpreter");
    chmod(interp, 0755);

    /* User-private-group relaxation: group-write passes only when the
     * file's group is the file owner's primary group (equivalent to
     * owner-write on umask-002 systems); a shared group stays refused. */
    struct passwd *self_pw = getpwuid(getuid());
    if (self_pw != NULL
            && chown(interp, (uid_t)-1, self_pw->pw_gid) == 0) {
        chmod(interp, 0775);
        CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                                   so, sizeof so, NULL, err, sizeof err) == 0,
              "accepts a group-writable interpreter under the owner's "
              "primary group (UPG)");
        chmod(interp, 0755);
    } else {
        printf("skip UPG interpreter case (no passwd entry for uid)\n");
    }

    gid_t shared_gid = (gid_t)-1;
    if (self_pw != NULL) {
        gid_t groups[64];
        int ng = getgroups(64, groups);
        for (int i = 0; i < ng; i++) {
            if (groups[i] != self_pw->pw_gid) {
                shared_gid = groups[i];
                break;
            }
        }
    }
    if (shared_gid != (gid_t)-1
            && chown(interp, (uid_t)-1, shared_gid) == 0) {
        chmod(interp, 0775);
        CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                                   so, sizeof so, NULL, err, sizeof err) != 0
                  && strstr(err, "primary group") != NULL,
              "refuses a group-writable interpreter under a shared "
              "(non-primary) group");
        chmod(interp, 0755);
        if (chown(interp, (uid_t)-1, self_pw->pw_gid) != 0) {
            printf("note: could not restore the interpreter's group\n");
        }
    } else {
        printf("skip shared-group interpreter case (no distinct "
               "supplementary group)\n");
    }

    chmod(script, 0666);
    CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                               so, sizeof so, NULL, err, sizeof err) != 0
              && strstr(err, "coordinator script") != NULL,
          "refuses an other-writable pinned script");
    chmod(script, 0644);

    if (self_pw != NULL
            && chown(script, (uid_t)-1, self_pw->pw_gid) == 0) {
        chmod(script, 0664);
        CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                                   so, sizeof so, NULL, err, sizeof err) == 0,
              "accepts a UPG group-writable pinned script (mode 0664)");
        chmod(script, 0644);
    }

    chmod(helpers, 0777);
    CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                               so, sizeof so, NULL, err, sizeof err) != 0
              && strstr(err, "directory") != NULL,
          "refuses an other-writable helpers directory");
    chmod(helpers, 0755);

    if (self_pw != NULL
            && chown(helpers, (uid_t)-1, self_pw->pw_gid) == 0) {
        chmod(helpers, 0775);
        CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                                   so, sizeof so, NULL, err, sizeof err) == 0,
              "accepts a UPG group-writable helpers directory "
              "(mode 0775)");
        chmod(helpers, 0755);
    }
    if (shared_gid != (gid_t)-1
            && chown(helpers, (uid_t)-1, shared_gid) == 0) {
        chmod(helpers, 0775);
        CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                                   so, sizeof so, NULL, err, sizeof err) != 0
                  && strstr(err, "primary group") != NULL,
              "refuses a shared-group-writable helpers directory");
        chmod(helpers, 0755);
        if (chown(helpers, (uid_t)-1, self_pw->pw_gid) != 0) {
            printf("note: could not restore the helpers dir group\n");
        }
    }

    /* Opportunistic real-system shared-group case (covers hosts where
     * the invoker has no distinct supplementary group to chgrp with):
     * Debian/Ubuntu ship root-owned directories that are group-writable
     * by a group which is NOT root's primary group (/var/mail is
     * root:mail 2775). check_trusted_path must refuse those. */
    {
        const char *candidates[] = { "/var/mail", "/var/local", NULL };
        struct passwd *root_pw = getpwuid(0);
        int exercised = 0;
        for (int i = 0; candidates[i] != NULL && !exercised; i++) {
            struct stat sst;
            if (root_pw != NULL
                    && stat(candidates[i], &sst) == 0
                    && S_ISDIR(sst.st_mode)
                    && sst.st_uid == 0
                    && (sst.st_mode & S_IWGRP)
                    && !(sst.st_mode & S_IWOTH)
                    && sst.st_gid != root_pw->pw_gid) {
                CHECK(check_trusted_path(candidates[i], getuid(), 1,
                                         "system directory", err,
                                         sizeof err) != 0
                          && strstr(err, "primary group") != NULL,
                      "refuses a root-owned dir group-writable by a "
                      "non-primary group");
                exercised = 1;
            }
        }
        if (!exercised) {
            printf("skip system shared-group dir case (no suitable "
                   "candidate on this host)\n");
        }
    }

    CHECK(validate_exec_target(3, argv_ok, launcher, io, sizeof io,
                               so, sizeof so, NULL, err, sizeof err) == 0,
          "accepts again once modes are restored");

    /* Ownership rule, exercised directly: a file owned by this uid is
     * refused when the trusted uid is a DIFFERENT non-root uid (a local
     * user cannot create files owned by root or by the operator). Only
     * meaningful when we are not root — root-owned files always pass. */
    if (getuid() != 0) {
        CHECK(check_trusted_path(interp, getuid() + 1, 0, "interpreter",
                                 err, sizeof err) != 0
                  && strstr(err, "owned by") != NULL,
              "trusted-path refuses a file owned by neither root nor "
              "the launcher owner");
    } else {
        printf("skip trusted-path foreign-owner case (running as root)\n");
    }

    /* A root-owned system interpreter passes the uid-0 branch. */
    struct stat st;
    if (stat("/usr/bin/python3", &st) == 0 && st.st_uid == 0
            && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0) {
        char *argv_sys[] = { launcher, (char *)"/usr/bin/python3", script,
                             NULL };
        CHECK(validate_exec_target(3, argv_sys, launcher, io, sizeof io,
                                   so, sizeof so, NULL, err, sizeof err) == 0,
              "accepts a root-owned system interpreter");
    } else {
        printf("skip root-owned interpreter case (/usr/bin/python3 "
               "unsuitable)\n");
    }

    unlink(other);
    unlink(interp);
    unlink(script);
    unlink(launcher);
    rmdir(helpers);
    rmdir(base);
}


/* ------------------------------------------------------------------ */
/* raptor-coord-launcher: derive_raptor_dir                             */
/* ------------------------------------------------------------------ */

static void test_derive_raptor_dir(void) {
    char out[PATH_MAX];
    char err[512];

    CHECK(derive_raptor_dir(
              "/home/op/raptor/core/sandbox/netns_coordinator.py",
              out, sizeof out, err, sizeof err) == 0
              && strcmp(out, "/home/op/raptor") == 0,
          "derives the checkout root from the pinned script path");
    CHECK(derive_raptor_dir("/core/sandbox/netns_coordinator.py",
                            out, sizeof out, err, sizeof err) == 0
              && strcmp(out, "/") == 0,
          "derives '/' for a checkout at the filesystem root");
    CHECK(derive_raptor_dir("/home/op/raptor/netns_coordinator.py",
                            out, sizeof out, err, sizeof err) != 0
              && strstr(err, "import-root derivation") != NULL,
          "refuses a coordinator path at the wrong checkout depth");
    CHECK(derive_raptor_dir("/home/op/raptor/core/sandbox/other.py",
                            out, sizeof out, err, sizeof err) != 0,
          "refuses a non-coordinator script name");
    CHECK(derive_raptor_dir("core/sandbox/netns_coordinator.py",
                            out, sizeof out, err, sizeof err) != 0,
          "refuses a relative script path");
    CHECK(derive_raptor_dir(
              "/home/opcore/sandbox/netns_coordinator.py",
              out, sizeof out, err, sizeof err) != 0,
          "refuses a suffix match that is not on a component boundary");
    char tiny[4];
    CHECK(derive_raptor_dir(
              "/home/op/raptor/core/sandbox/netns_coordinator.py",
              tiny, sizeof tiny, err, sizeof err) != 0,
          "refuses when the root exceeds the caller buffer");
}


/* ------------------------------------------------------------------ */
/* raptor-coord-launcher: check_invoker_identity                        */
/* ------------------------------------------------------------------ */

static void test_invoker_identity(void) {
    char err[512];

    CHECK(check_invoker_identity(1000, 1000, 1000, err, sizeof err) == 0,
          "accepts the trusted owner (uid==euid==owner)");
    CHECK(check_invoker_identity(0, 0, 1000, err, sizeof err) == 0,
          "accepts root regardless of the owner uid");
    CHECK(check_invoker_identity(0, 0, 0, err, sizeof err) == 0,
          "accepts root for a root-owned install");
    CHECK(check_invoker_identity(1001, 1001, 1000, err, sizeof err) != 0
              && strstr(err, "invoker identity") != NULL,
          "refuses a foreign local user");
    CHECK(check_invoker_identity(1000, 1001, 1000, err, sizeof err) != 0,
          "refuses when only the real uid matches (euid differs)");
    CHECK(check_invoker_identity(1001, 1000, 1000, err, sizeof err) != 0,
          "refuses when only the effective uid matches (uid differs)");
    CHECK(check_invoker_identity(1000, 1000, 0, err, sizeof err) != 0,
          "refuses a non-root invoker of a root-owned install");
    CHECK(check_invoker_identity(0, 1000, 1000, err, sizeof err) != 0,
          "refuses a mixed root/non-root identity");
}


/* ------------------------------------------------------------------ */
/* raptor-gidmap-allow: parse_strict_ulong / validate_mapping_args      */
/* ------------------------------------------------------------------ */

static void test_parse_strict_ulong(void) {
    unsigned long v = 0;
    CHECK(parse_strict_ulong("0", &v) == 0 && v == 0,
          "parses '0'");
    CHECK(parse_strict_ulong("4294967294", &v) == 0 && v == 4294967294UL,
          "parses a large gid");
    CHECK(parse_strict_ulong("", &v) != 0, "rejects empty string");
    CHECK(parse_strict_ulong("-1", &v) != 0, "rejects '-1'");
    CHECK(parse_strict_ulong("+3", &v) != 0, "rejects '+3'");
    CHECK(parse_strict_ulong(" 5", &v) != 0, "rejects leading whitespace");
    CHECK(parse_strict_ulong("12x", &v) != 0, "rejects trailing garbage");
    CHECK(parse_strict_ulong("0x10", &v) != 0, "rejects hex notation");
    CHECK(parse_strict_ulong("99999999999999999999999", &v) != 0,
          "rejects out-of-range values");
}


static void test_mapping_args(void) {
    gid_t two[] = { 1000, 1001 };
    gid_t one[] = { 1000 };
    unsigned long pid = 0;
    char err[512];

    char *ok[] = { (char *)"prog", (char *)"1234", (char *)"0",
                   (char *)"1000", (char *)"1", NULL };
    CHECK(validate_mapping_args(5, ok, two, 2, &pid, err, sizeof err) == 0
              && pid == 1234,
          "accepts the RAPTOR call shape (single triple, own gid)");

    char *foreign[] = { (char *)"prog", (char *)"1234", (char *)"0",
                        (char *)"999", (char *)"1", NULL };
    CHECK(validate_mapping_args(5, foreign, two, 2, &pid, err,
                                sizeof err) != 0
              && strstr(err, "gid confinement") != NULL,
          "refuses a host gid the invoker does not hold");

    char *badpid[] = { (char *)"prog", (char *)"12x", (char *)"0",
                       (char *)"1000", (char *)"1", NULL };
    CHECK(validate_mapping_args(5, badpid, two, 2, &pid, err,
                                sizeof err) != 0,
          "refuses a non-numeric PID");
    char *zeropid[] = { (char *)"prog", (char *)"0", (char *)"0",
                        (char *)"1000", (char *)"1", NULL };
    CHECK(validate_mapping_args(5, zeropid, two, 2, &pid, err,
                                sizeof err) != 0,
          "refuses PID 0");
    char *badgid[] = { (char *)"prog", (char *)"1234", (char *)"0",
                       (char *)"10 00", (char *)"1", NULL };
    CHECK(validate_mapping_args(5, badgid, two, 2, &pid, err,
                                sizeof err) != 0,
          "refuses a non-numeric host gid");

    CHECK(validate_mapping_args(4, ok, two, 2, &pid, err, sizeof err) != 0,
          "refuses a truncated triple");
    CHECK(validate_mapping_args(1, ok, two, 2, &pid, err, sizeof err) != 0,
          "refuses no arguments");

    char *count0[] = { (char *)"prog", (char *)"1234", (char *)"0",
                       (char *)"1000", (char *)"0", NULL };
    CHECK(validate_mapping_args(5, count0, two, 2, &pid, err,
                                sizeof err) != 0,
          "refuses count 0");
    char *bigcount[] = { (char *)"prog", (char *)"1234", (char *)"0",
                         (char *)"1000", (char *)"70000", NULL };
    CHECK(validate_mapping_args(5, bigcount, two, 2, &pid, err,
                                sizeof err) != 0,
          "refuses an oversized count");

    char *span2[] = { (char *)"prog", (char *)"1234", (char *)"0",
                      (char *)"1000", (char *)"2", NULL };
    CHECK(validate_mapping_args(5, span2, two, 2, &pid, err,
                                sizeof err) == 0,
          "accepts a count-2 range fully inside the invoker's gids");
    CHECK(validate_mapping_args(5, span2, one, 1, &pid, err,
                                sizeof err) != 0
              && strstr(err, "gid confinement") != NULL,
          "refuses a count-2 range that leaves the invoker's gids");

    char *wrap[] = { (char *)"prog", (char *)"1234", (char *)"0",
                     (char *)"4294967294", (char *)"2", NULL };
    CHECK(validate_mapping_args(5, wrap, two, 2, &pid, err,
                                sizeof err) != 0,
          "refuses a range that exceeds the valid gid space");

    /* 9 triples (one over the bound): argc = 2 + 27 = 29. */
    char *many[29 + 1];
    many[0] = (char *)"prog";
    many[1] = (char *)"1234";
    for (int t = 0; t < 9; t++) {
        many[2 + 3 * t] = (char *)"0";
        many[3 + 3 * t] = (char *)"1000";
        many[4 + 3 * t] = (char *)"1";
    }
    many[29] = NULL;
    CHECK(validate_mapping_args(29, many, two, 2, &pid, err,
                                sizeof err) != 0
              && strstr(err, "triples") != NULL,
          "refuses more than 8 mapping triples");
    CHECK(validate_mapping_args(26, many, two, 2, &pid, err,
                                sizeof err) == 0,
          "accepts exactly 8 mapping triples");
}


/* ------------------------------------------------------------------ */
/* raptor-gidmap-allow: check_ns_owner                                  */
/* ------------------------------------------------------------------ */

static void test_ns_owner(void) {
    char err[512];

    /* Probe: fork a child that creates its own user namespace. Needs no
     * privilege where unprivileged userns is permitted; skip gracefully
     * where the host blocks it. */
    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) {
        fprintf(stderr, "harness: pipe: %s\n", strerror(errno));
        exit(1);
    }
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "harness: fork: %s\n", strerror(errno));
        exit(1);
    }
    if (child == 0) {
        close(sync_pipe[0]);
        char c = unshare(CLONE_NEWUSER) == 0 ? 'Y' : 'N';
        if (write(sync_pipe[1], &c, 1) != 1) _exit(1);
        if (c == 'Y') {
            for (;;) pause();   /* parent inspects, then kills us */
        }
        _exit(0);
    }
    close(sync_pipe[1]);
    char c = 0;
    ssize_t n = read(sync_pipe[0], &c, 1);
    close(sync_pipe[0]);
    if (n != 1 || c != 'Y') {
        printf("skip ns-owner cases (host blocks unprivileged "
               "unshare(CLONE_NEWUSER))\n");
        waitpid(child, NULL, 0);
        return;
    }

    int proc_fd = open_proc_pid_dir((unsigned long)child, err, sizeof err);
    CHECK(proc_fd >= 0, "opens a live pid's /proc dir as the pinned fd");
    CHECK(check_ns_owner_at(proc_fd, (unsigned long)child, getuid(), err,
                            sizeof err) == 0,
          "accepts a self-created user namespace");
    CHECK(check_ns_owner_at(proc_fd, (unsigned long)child, getuid() + 1,
                            err, sizeof err) != 0
              && strstr(err, "namespace ownership") != NULL,
          "refuses when the owner uid differs from the invoker");

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    /* PID-reuse pin: once the validated process is gone, the pinned
     * dirfd must go stale — BOTH the ns re-check and a gid_map open
     * through it must fail, no matter what new process now holds the
     * numeric pid. This is the property that makes the check-then-write
     * sequence in main() race-free. */
    CHECK(check_ns_owner_at(proc_fd, (unsigned long)child, getuid(), err,
                            sizeof err) != 0,
          "pinned dirfd refuses the ns check after the process exits");
    int stale_map = openat(proc_fd, "gid_map", O_WRONLY | O_CLOEXEC);
    CHECK(stale_map < 0,
          "pinned dirfd refuses a gid_map open after the process exits");
    if (stale_map >= 0) close(stale_map);
    close(proc_fd);

    if (getuid() != 0) {
        /* pid 1 lives in the init user namespace (owned by root); an
         * unprivileged invoker is refused either at the ns/user open()
         * or at the owner comparison. */
        int init_fd = open_proc_pid_dir(1, err, sizeof err);
        if (init_fd >= 0) {
            CHECK(check_ns_owner_at(init_fd, 1, getuid(), err,
                                    sizeof err) != 0,
                  "refuses pid 1 (init user namespace)");
            close(init_fd);
        } else {
            CHECK(1, "refuses pid 1 (init user namespace, at dir open)");
        }
    } else {
        printf("skip pid-1 ns-owner case (running as root)\n");
    }

    /* A vanished pid is refused at the /proc dir open. */
    CHECK(open_proc_pid_dir(0x7fffffffUL, err, sizeof err) < 0,
          "refuses a nonexistent pid");
}


int main(void) {
    test_exec_target();
    test_derive_raptor_dir();
    test_invoker_identity();
    test_parse_strict_ulong();
    test_mapping_args();
    test_ns_owner();
    if (failures > 0) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("all helper contract checks passed\n");
    return 0;
}
