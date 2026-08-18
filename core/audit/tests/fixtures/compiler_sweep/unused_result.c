__attribute__((warn_unused_result)) static int must_check(int x) {
    return x + 1;
}

int ignores_result(int v) {
    must_check(v);
    return 0;
}

int checks_result(int v) {
    if (must_check(v) != 0)
        return 1;
    return 0;
}
