// trace_instrument.c - Function call tracing instrumentation
// Compile: gcc -c -fPIC trace_instrument.c -o trace_instrument.o
//          gcc -shared trace_instrument.o -o libtrace.so -ldl -lpthread

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/syscall.h>

typedef struct {
    FILE *logfile;
    unsigned long sequence;
    int depth;
    pid_t tid;
} thread_state_t;

static pthread_key_t thread_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

static void make_thread_key(void) {
    pthread_key_create(&thread_key, NULL);
}

static pid_t gettid(void) {
    return syscall(SYS_gettid);
}

static thread_state_t* get_thread_state(void) {
    pthread_once(&key_once, make_thread_key);
    
    thread_state_t *state = pthread_getspecific(thread_key);
    if (!state) {
        state = calloc(1, sizeof(thread_state_t));
        state->tid = gettid();
        
        char filename[256];
        snprintf(filename, sizeof(filename), "trace_%d.log", state->tid);
        state->logfile = fopen(filename, "w");
        if (state->logfile) {
            setvbuf(state->logfile, NULL, _IOLBF, 0);
        }
        
        pthread_setspecific(thread_key, state);
    }
    
    return state;
}

static const char* get_function_name(void *func_addr) {
    Dl_info info;
    if (dladdr(func_addr, &info) && info.dli_sname) {
        return info.dli_sname;
    }
    static __thread char addr_buf[32];
    snprintf(addr_buf, sizeof(addr_buf), "0x%lx", (unsigned long)func_addr);
    return addr_buf;
}

static void get_timestamp(char *buf, size_t bufsize) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    snprintf(buf, bufsize, "%ld.%09ld", ts.tv_sec, ts.tv_nsec);
}

void __cyg_profile_func_enter(void *func_addr, void *call_site)
    __attribute__((no_instrument_function));

void __cyg_profile_func_enter(void *func_addr, void *call_site) {
    thread_state_t *state = get_thread_state();
    if (!state || !state->logfile) return;
    
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(state->logfile, "[%lu] [%s] ", state->sequence++, timestamp);
    for (int i = 0; i < state->depth; i++) fputc('.', state->logfile);
    fprintf(state->logfile, " [ENTRY] %s\n", get_function_name(func_addr));
    
    state->depth++;
}

void __cyg_profile_func_exit(void *func_addr, void *call_site)
    __attribute__((no_instrument_function));

void __cyg_profile_func_exit(void *func_addr, void *call_site) {
    thread_state_t *state = get_thread_state();
    if (!state || !state->logfile) return;
    
    state->depth--;
    
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(state->logfile, "[%lu] [%s] ", state->sequence++, timestamp);
    for (int i = 0; i < state->depth; i++) fputc('.', state->logfile);
    fprintf(state->logfile, " [EXIT!] %s\n", get_function_name(func_addr));
}
