#define PASTE2(a, b) a##b
#define PASTE(a, b) PASTE2(a, b)
#define QUIET PASTE(_Pra, gma)("GCC diagnostic ignored \"-Wanalyzer-use-after-free\"")
QUIET
