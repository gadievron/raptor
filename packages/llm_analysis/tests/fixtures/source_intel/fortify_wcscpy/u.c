#include <wchar.h>
extern wchar_t *wcscpy(wchar_t *dst, const wchar_t *src);

int op(const wchar_t *src) {
    wchar_t buf[32];
    wcscpy(buf, src);  /* FORTIFY rewrites to __wcscpy_chk */
    return 0;
}
