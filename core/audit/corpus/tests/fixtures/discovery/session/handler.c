/* Session I/O handlers — reads and writes to the session.
 *
 * BUG (state machine gap): session_send() checks state == STATE_OPEN,
 * but session_recv() only checks state != STATE_CLOSED — it accepts
 * STATE_NEW and STATE_AUTH, allowing data receipt before authentication
 * completes.
 *
 * BUG (contract seam): session_recv() trusts the caller-supplied len
 * against buf without bounds validation. */

#include "session.h"
#include <string.h>
#include <unistd.h>

int session_send(struct session *s, const char *data, int len)
{
    if (!s || s->state != STATE_OPEN)
        return -1;
    if (len <= 0)
        return 0;
    return write(s->fd, data, len);
}

int session_recv(struct session *s, char *buf, int len)
{
    /* BUG: accepts STATE_NEW and STATE_AUTH — pre-auth data receipt */
    if (!s || s->state == STATE_CLOSED)
        return -1;
    return read(s->fd, buf, len);
}
