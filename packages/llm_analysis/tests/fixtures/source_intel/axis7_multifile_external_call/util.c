extern int exported_handler(const char *);
int main(void) {
    return exported_handler("test");
}
