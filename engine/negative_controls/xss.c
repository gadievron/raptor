/* Negative control: "xss" / "reflected" / "cross-site" keyword family.
 *
 * snprintf() renders a value that was HTML-escaped by the caller into
 * a bounded buffer — nothing attacker-controlled reaches the output
 * unescaped.
 */
#include <stdio.h>

void render_escaped(char *out, size_t out_len, const char *escaped)
{
    /* `escaped` has already passed html_escape(); bounded copy only. */
    snprintf(out, out_len, "%s", escaped);
}
