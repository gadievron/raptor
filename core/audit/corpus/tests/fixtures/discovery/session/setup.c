/* Session setup — creates and authenticates.
 *
 * session_create() initialises state to STATE_NEW.
 * session_auth() transitions STATE_NEW → STATE_AUTH → STATE_OPEN. */

#include "session.h"
#include <stdlib.h>
#include <string.h>

struct session *session_create(int fd)
{
    struct session *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->state = STATE_NEW;
    s->fd = fd;
    return s;
}

int session_auth(struct session *s, const char *user, const char *pass)
{
    if (!s || s->state != STATE_NEW)
        return -1;

    if (strlen(user) >= sizeof(s->user))
        return -1;

    s->state = STATE_AUTH;
    strcpy(s->user, user);

    /* Toy credential check */
    if (strcmp(pass, "hunter2") != 0) {
        s->state = STATE_NEW;
        return -1;
    }

    s->is_admin = (strcmp(user, "root") == 0);
    s->state = STATE_OPEN;
    return 0;
}
