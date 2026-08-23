#ifndef HANDLERS_H
#define HANDLERS_H

#define DEFINE_HANDLER(name) \
    int handler_##name(int value) { return value + 1; }

#endif
