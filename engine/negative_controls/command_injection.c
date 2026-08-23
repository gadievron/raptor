/* Negative control: "command injection" keyword family.
 *
 * execv() with a fixed binary path and a fixed argv — no attacker
 * input reaches the command line, so nothing can be injected.
 */
#include <unistd.h>

void run_sync(void)
{
    char *const argv[] = {"sync", (char *)0};
    execv("/usr/bin/sync", argv); /* constant program and arguments */
}
