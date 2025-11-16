/*
 * Simple vulnerable program for testing RAPTOR fuzzing mode
 *
 * Compile with:
 *   gcc -o vulnerable_test vulnerable_test.c -g -O0 -fno-stack-protector
 *
 * Or with AFL instrumentation:
 *   afl-gcc -o vulnerable_test vulnerable_test.c -g -O0 -fno-stack-protector
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];

    // Classic stack overflow - no bounds checking!
    strcpy(buffer, input);

    printf("Input processed: %s\n", buffer);
}

void secret_function() {
    printf("🎉 You've reached the secret function!\n");
    printf("This demonstrates successful exploitation.\n");
}

int main(int argc, char **argv) {
    char input[1024];

    printf("Vulnerable Test Program\n");
    printf("=======================\n");

    // Read from stdin
    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }

    // Remove newline
    input[strcspn(input, "\n")] = 0;

    printf("Received %lu bytes\n", strlen(input));

    // Call vulnerable function
    vulnerable_function(input);

    printf("Program completed successfully\n");
    return 0;
}
