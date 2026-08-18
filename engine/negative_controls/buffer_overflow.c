/* Negative control: "buffer overflow" keyword family.
 *
 * Uses strcpy() with the source length verified against the destination
 * capacity first, so there is no overflow.  A rule that still matches
 * here fires on API presence, not on the vulnerability.
 */
#include <string.h>

void copy_name(char *dst, size_t dst_len, const char *src)
{
    if (strlen(src) + 1 > dst_len) {
        return;
    }
    strcpy(dst, src); /* bounded: length checked above */
}
