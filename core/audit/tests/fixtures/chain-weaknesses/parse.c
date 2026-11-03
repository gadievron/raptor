#include <stdlib.h>
#include <string.h>

/* Weakness: returns user-controlled length without upper-bound
   validation.  Not a vulnerability alone — the caller might check. */
size_t parse_content_length(const char *header) {
    const char *p = strstr(header, "Content-Length: ");
    if (!p)
        return 0;
    return (size_t)atol(p + 16);
}
