/*
 * RAPTOR Test Bench - Comprehensive Vulnerability Test Binary
 *
 * This binary contains multiple deliberate vulnerabilities for testing
 * RAPTOR's autonomous fuzzing capabilities:
 *
 * 1. Stack Buffer Overflow
 * 2. Heap Buffer Overflow
 * 3. Use-After-Free
 * 4. Parser Overflow (JSON/XML)
 * 5. Format String Vulnerability
 * 6. Integer Overflow
 * 7. Null Pointer Dereference
 *
 * Input Format:
 *   COMMAND:DATA
 *
 * Commands:
 *   STACK:data       - Trigger stack buffer overflow
 *   HEAP:data        - Trigger heap buffer overflow
 *   UAF:data         - Trigger use-after-free
 *   JSON:data        - Trigger JSON parser overflow
 *   XML:data         - Trigger XML parser overflow
 *   FMT:data         - Trigger format string bug
 *   INT:data         - Trigger integer overflow
 *   NULL:data        - Trigger null pointer dereference
 *
 * Compile:
 *   With AFL: afl-clang-fast -o raptor_testbench_afl raptor_testbench.c
 *   With ASAN: afl-clang-fast -fsanitize=address -o raptor_testbench_asan raptor_testbench.c
 *   Normal: gcc -o raptor_testbench raptor_testbench.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Global for use-after-free testing
char *global_buffer = NULL;

// =============================================================================
// 1. STACK BUFFER OVERFLOW
// =============================================================================
void vuln_stack_overflow(const char *data) {
    char buffer[64];  // Vulnerable buffer

    printf("[STACK] Processing: %s\n", data);

    // VULNERABILITY: No bounds checking
    strcpy(buffer, data);  // Overflow if data > 64 bytes

    printf("[STACK] Buffer contents: %s\n", buffer);
}

// =============================================================================
// 2. HEAP BUFFER OVERFLOW
// =============================================================================
void vuln_heap_overflow(const char *data) {
    char *heap_buffer = malloc(128);  // Vulnerable heap buffer

    printf("[HEAP] Processing: %s\n", data);

    if (heap_buffer == NULL) {
        fprintf(stderr, "[HEAP] malloc failed\n");
        return;
    }

    // VULNERABILITY: No bounds checking
    strcpy(heap_buffer, data);  // Overflow if data > 128 bytes

    printf("[HEAP] Buffer contents: %s\n", heap_buffer);

    free(heap_buffer);
}

// =============================================================================
// 3. USE-AFTER-FREE
// =============================================================================
void vuln_use_after_free(const char *data) {
    printf("[UAF] Processing: %s\n", data);

    // Allocate buffer
    global_buffer = malloc(256);
    if (global_buffer == NULL) {
        fprintf(stderr, "[UAF] malloc failed\n");
        return;
    }

    strcpy(global_buffer, data);
    printf("[UAF] Allocated buffer: %s\n", global_buffer);

    // Free the buffer
    free(global_buffer);
    printf("[UAF] Buffer freed\n");

    // VULNERABILITY: Use after free
    if (strlen(data) > 10) {
        printf("[UAF] Accessing freed memory: %s\n", global_buffer);  // Use-after-free!
        strcpy(global_buffer, "CORRUPTED");  // Write to freed memory
    }
}

// =============================================================================
// 4. JSON PARSER OVERFLOW
// =============================================================================
void vuln_json_parser(const char *data) {
    char json_buffer[256];
    char key[64];
    char value[64];

    printf("[JSON] Parsing: %s\n", data);

    // Simple JSON parser (vulnerable)
    if (data[0] == '{') {
        // Extract key-value pair: {"key":"value"}
        const char *key_start = strchr(data, '"');
        if (key_start == NULL) return;

        key_start++;
        const char *key_end = strchr(key_start, '"');
        if (key_end == NULL) return;

        // VULNERABILITY: No bounds checking
        strncpy(key, key_start, key_end - key_start);  // Potential overflow
        key[key_end - key_start] = '\0';

        const char *value_start = strchr(key_end + 1, '"');
        if (value_start == NULL) return;

        value_start++;
        const char *value_end = strchr(value_start, '"');
        if (value_end == NULL) return;

        // VULNERABILITY: No bounds checking on value
        strncpy(value, value_start, value_end - value_start);  // Overflow if value > 64
        value[value_end - value_start] = '\0';

        sprintf(json_buffer, "Parsed: %s=%s", key, value);  // Another potential overflow
        printf("[JSON] %s\n", json_buffer);
    }
}

// =============================================================================
// 5. XML PARSER OVERFLOW
// =============================================================================
void vuln_xml_parser(const char *data) {
    char tag_name[32];
    char tag_content[128];

    printf("[XML] Parsing: %s\n", data);

    // Simple XML parser (vulnerable)
    if (data[0] == '<') {
        const char *tag_start = data + 1;
        const char *tag_end = strchr(tag_start, '>');

        if (tag_end == NULL) return;

        // VULNERABILITY: No bounds checking
        size_t tag_len = tag_end - tag_start;
        strncpy(tag_name, tag_start, tag_len);  // Overflow if tag_len > 32
        tag_name[tag_len] = '\0';

        // Extract content
        const char *content_start = tag_end + 1;
        const char *content_end = strchr(content_start, '<');

        if (content_end == NULL) {
            // No closing tag, just copy rest
            strcpy(tag_content, content_start);  // VULNERABILITY: unbounded copy
        } else {
            size_t content_len = content_end - content_start;
            strncpy(tag_content, content_start, content_len);  // Overflow if > 128
            tag_content[content_len] = '\0';
        }

        printf("[XML] Tag: %s, Content: %s\n", tag_name, tag_content);
    }
}

// =============================================================================
// 6. FORMAT STRING VULNERABILITY
// =============================================================================
void vuln_format_string(const char *data) {
    char buffer[128];

    printf("[FMT] Processing format string\n");

    // VULNERABILITY: User data used as format string
    snprintf(buffer, sizeof(buffer), data);  // If data contains %s, %n, etc.

    printf("[FMT] Result: %s\n", buffer);
}

// =============================================================================
// 7. INTEGER OVERFLOW
// =============================================================================
void vuln_integer_overflow(const char *data) {
    unsigned int size = atoi(data);

    printf("[INT] Allocating %u bytes\n", size);

    // VULNERABILITY: Integer overflow in allocation
    unsigned int alloc_size = size + 100;  // Can overflow if size is large

    if (alloc_size < size) {
        printf("[INT] Integer overflow detected!\n");
    }

    char *buffer = malloc(alloc_size);
    if (buffer == NULL) {
        fprintf(stderr, "[INT] malloc failed\n");
        return;
    }

    // Write beyond intended bounds
    memset(buffer, 'A', size + 50);  // Heap overflow

    printf("[INT] Buffer allocated and filled\n");
    free(buffer);
}

// =============================================================================
// 8. NULL POINTER DEREFERENCE
// =============================================================================
void vuln_null_pointer(const char *data) {
    char *ptr = NULL;

    printf("[NULL] Processing: %s\n", data);

    // VULNERABILITY: Null pointer dereference
    if (strlen(data) > 5 && data[0] == 'N') {
        printf("[NULL] Dereferencing null pointer\n");
        strcpy(ptr, data);  // NULL pointer dereference!
    }
}

// =============================================================================
// MAIN DISPATCHER
// =============================================================================
int main(int argc, char **argv) {
    char input[4096];

    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║         RAPTOR Test Bench - Vulnerability Suite               ║\n");
    printf("║                                                               ║\n");
    printf("║  Commands: STACK, HEAP, UAF, JSON, XML, FMT, INT, NULL        ║\n");
    printf("║  Format: COMMAND:DATA                                         ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");

    // Read input from stdin
    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }

    // Remove newline
    input[strcspn(input, "\n")] = '\0';

    printf("Received: %s\n\n", input);

    // Parse command
    char *colon = strchr(input, ':');
    if (colon == NULL) {
        fprintf(stderr, "Invalid format. Use: COMMAND:DATA\n");
        return 1;
    }

    *colon = '\0';
    char *command = input;
    char *data = colon + 1;

    // Dispatch to vulnerability handler
    if (strcmp(command, "STACK") == 0) {
        vuln_stack_overflow(data);
    }
    else if (strcmp(command, "HEAP") == 0) {
        vuln_heap_overflow(data);
    }
    else if (strcmp(command, "UAF") == 0) {
        vuln_use_after_free(data);
    }
    else if (strcmp(command, "JSON") == 0) {
        vuln_json_parser(data);
    }
    else if (strcmp(command, "XML") == 0) {
        vuln_xml_parser(data);
    }
    else if (strcmp(command, "FMT") == 0) {
        vuln_format_string(data);
    }
    else if (strcmp(command, "INT") == 0) {
        vuln_integer_overflow(data);
    }
    else if (strcmp(command, "NULL") == 0) {
        vuln_null_pointer(data);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", command);
        fprintf(stderr, "Available: STACK, HEAP, UAF, JSON, XML, FMT, INT, NULL\n");
        return 1;
    }

    printf("\n[SUCCESS] Completed without crash\n");
    return 0;
}
