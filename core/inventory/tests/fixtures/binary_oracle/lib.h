#ifndef BINARY_ORACLE_FIXTURE_LIB_H
#define BINARY_ORACLE_FIXTURE_LIB_H

int live_called(int x);
int live_address_taken_target(int x);
int inlined_only_user(int x);
int dead_extern_unused(int x);
int folded_a(int x);
int folded_b(int x);
int volatile_call_target(int x);
int indirect_caller(int x);

extern int (*GLOBAL_TABLE[])(int);
extern int (*GLOBAL_TABLE2[])(int);

#endif
