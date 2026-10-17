/* Session teardown — closes the session.
 *
 * BUG (state machine gap): session_close() sets STATE_CLOSED and
 * frees the session without draining tx_head.  Any queued tx_entry
 * nodes leak, and a concurrent session_send() racing the close sees
 * STATE_OPEN → writes to a freed fd.
 *
 * BUG (double-free): session_close() does not NULL-check or clear
 * the pointer — calling it twice double-frees. */

#include "session.h"
#include <stdlib.h>
#include <unistd.h>

void session_close(struct session *s)
{
    if (!s)
        return;
    /* BUG: tx_head not drained — queued entries leak */
    s->state = STATE_CLOSED;
    close(s->fd);
    free(s);
    /* BUG: caller still holds dangling pointer */
}
