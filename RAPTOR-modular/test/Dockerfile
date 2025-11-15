FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential clang afl++ pkg-config wget git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY vuln_fuzz_target.c /work/

# build fully unprotected ELF binary
RUN afl-clang-fast -g -O2 \
    -fno-stack-protector \
    -D_FORTIFY_SOURCE=0 \
    -fno-builtin \
    -Wl,-z,norelro \
    -Wl,-z,execstack \
    -no-pie \
    -o vuln_fuzz_target_unprotected vuln_fuzz_target.c

