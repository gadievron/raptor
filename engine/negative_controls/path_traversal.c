/* Negative control: "path traversal" keyword family.
 *
 * open() on a joined path only after realpath() containment check —
 * a "../" component cannot escape the base directory.
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int open_within(const char *base, const char *name)
{
    char joined[PATH_MAX];
    char resolved[PATH_MAX];
    char base_real[PATH_MAX];

    if (snprintf(joined, sizeof(joined), "%s/%s", base, name)
            >= (int)sizeof(joined)) {
        return -1;
    }
    if (!realpath(joined, resolved) || !realpath(base, base_real)) {
        return -1;
    }
    if (strncmp(resolved, base_real, strlen(base_real)) != 0) {
        return -1; /* escapes the base directory */
    }
    return open(resolved, O_RDONLY);
}
