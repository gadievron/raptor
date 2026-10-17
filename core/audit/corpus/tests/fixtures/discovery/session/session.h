/* Session state machine — shared header.
 *
 * Lifecycle: STATE_NEW → STATE_AUTH → STATE_OPEN → STATE_CLOSED
 *
 * Discovery fixture: state machine perspective should detect that
 * handler.c reads sess->state without checking for STATE_AUTH first
 * (skips authentication), and that teardown.c writes STATE_CLOSED
 * without draining the tx queue. */

#ifndef SESSION_H
#define SESSION_H

enum sess_state {
    STATE_NEW    = 0,
    STATE_AUTH   = 1,
    STATE_OPEN   = 2,
    STATE_CLOSED = 3,
};

struct tx_entry {
    struct tx_entry *next;
    char data[256];
    int  len;
};

struct session {
    enum sess_state  state;
    int              fd;
    int              is_admin;
    char             user[64];
    struct tx_entry *tx_head;
    int              tx_count;
};

struct session *session_create(int fd);
int  session_auth(struct session *s, const char *user, const char *pass);
int  session_send(struct session *s, const char *data, int len);
int  session_recv(struct session *s, char *buf, int len);
void session_close(struct session *s);

#endif
