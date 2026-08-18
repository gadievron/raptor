#ifdef ENABLE_FEATURE
int feature_on(int x) {
    return x;
}
#else
int feature_off(int x) {
    return -x;
}
#endif
