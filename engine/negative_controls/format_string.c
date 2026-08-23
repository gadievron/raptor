/* Negative control: "format string" keyword family.
 *
 * printf() with a compile-time-constant format — the user-controlled
 * value is only ever a %s argument, never the format itself.
 */
#include <stdio.h>

static const char *fmt = "%s\n"; /* constant format string */

void log_msg(const char *msg)
{
    printf(fmt, msg);
}
