extern int strcpy(char *d, const char *s);

#ifdef CONFIG_OPTIONAL_FEATURE
static int feature_handler(const char *user) {
    char buf[16];
    strcpy(buf, user);  /* sink: only compiled when CONFIG_OPTIONAL_FEATURE */
    return 0;
}

int feature_dispatch(void) {
    return feature_handler("test");
}
#endif

int main(void) { return 0; }
