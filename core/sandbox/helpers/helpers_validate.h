/* helpers_validate.h — argument-contract validation for RAPTOR's
 * capability-granted sandbox helpers.
 *
 * Each helper binary keeps its validation logic in standalone functions
 * (declared here, defined in the helper's own .c file) so that the exact
 * code that gates the privileged path can also be compiled into an
 * unprivileged test harness (helpers_test.c, built via `make test`).
 * When RAPTOR_HELPERS_TEST is defined the helpers' main() functions are
 * compiled out and only the validation functions remain, letting the
 * harness link both translation units together.
 *
 * All validators return 0 on acceptance and -1 on refusal, writing a
 * human-readable reason (naming the violated contract) into `err`.
 * They perform no privileged operation and require no capabilities.
 */

#ifndef RAPTOR_HELPERS_VALIDATE_H
#define RAPTOR_HELPERS_VALIDATE_H

#include <stddef.h>
#include <sys/types.h>

/* --- raptor-coord-launcher.c ------------------------------------- */

/* Trusted-path check on an already-canonicalised path: the object must
 * exist, be a regular file (or a directory when expect_dir is nonzero),
 * be owned by uid 0 or by `trusted_uid` (the launcher binary's owner,
 * i.e. the granting operator), and must not be writable by untrusted
 * parties: other-write is always refused; group-write is refused unless
 * the file's group is the file OWNER's primary group (the
 * user-private-group case — equivalent to owner-write, so umask-002
 * checkouts pass with zero configuration; shared-group write stays
 * refused). `what` names the object in refusal messages. */
int check_trusted_path(const char *path, uid_t trusted_uid, int expect_dir,
                       const char *what, char *err, size_t errsz);

/* Full exec-target contract for the coord launcher:
 *   - argc must be exactly 3: [launcher, interpreter, script]
 *   - realpath(argv[2]) must equal
 *     realpath(dirname(realpath(self_exe)) + "/../netns_coordinator.py")
 *   - launcher directory, script, and interpreter must each pass
 *     check_trusted_path() against the launcher binary's owner uid
 * On acceptance the canonicalised interpreter and script paths are
 * written to interp_out / script_out (the caller execs those, not the
 * raw argv values). */
int validate_exec_target(int argc, char **argv, const char *self_exe,
                         char *interp_out, size_t interp_cap,
                         char *script_out, size_t script_cap,
                         char *err, size_t errsz);

/* --- raptor-gidmap-allow.c ---------------------------------------- */

/* Strictly-numeric unsigned decimal parse: rejects empty strings, signs,
 * whitespace, hex/octal prefixes, trailing garbage, and out-of-range
 * values. Returns 0 and stores the value on success, -1 otherwise. */
int parse_strict_ulong(const char *s, unsigned long *out);

/* Mapping-argument contract for the gid_map helper:
 *   - argv shape: PID inside_gid host_gid count [triple ...]
 *   - at most RAPTOR_GIDMAP_MAX_TRIPLES triples, every component
 *     strictly numeric, pid > 0, count > 0 and bounded
 *   - every host gid covered by a triple's [host_gid, host_gid+count)
 *     range must appear in `allowed` (the invoker's real/effective gid
 *     and supplementary groups — file caps do not change real ids, so
 *     these are genuinely the caller's own gids)
 * On acceptance the parsed pid is stored in *pid_out. */
int validate_mapping_args(int argc, char **argv,
                          const gid_t *allowed, size_t n_allowed,
                          unsigned long *pid_out,
                          char *err, size_t errsz);

/* Namespace-ownership contract: the user namespace of `pid` must be
 * owned by `expect_uid` (checked via NS_GET_OWNER_UID on
 * /proc/<pid>/ns/user). Refuses when the ns cannot be opened, the ioctl
 * fails, or the owner differs. Requires no capabilities for namespaces
 * the invoker can already see. */
int check_ns_owner(unsigned long pid, uid_t expect_uid,
                   char *err, size_t errsz);

#define RAPTOR_GIDMAP_MAX_TRIPLES 8

#endif /* RAPTOR_HELPERS_VALIDATE_H */
