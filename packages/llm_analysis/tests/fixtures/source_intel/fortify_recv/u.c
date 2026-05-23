#include <stddef.h>
extern int recv(int fd, void *buf, size_t n, int flags);

int op(int fd) {
    char buf[64];
    recv(fd, buf, 256, 0);  /* FORTIFY catches size > obj_size */
    return 0;
}
