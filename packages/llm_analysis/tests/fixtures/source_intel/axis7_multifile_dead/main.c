extern int strcpy(char *d, const char *s);

static int unused_helper(const char *user) {
    char buf[16];
    strcpy(buf, user);
    return 0;
}

int main(void) { return 0; }
