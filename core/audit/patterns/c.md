# C Vulnerability Patterns

These patterns are specific to C (and largely C++). They exploit properties
of the C memory model, type system, and undefined behaviour that do not
exist in memory-safe languages. Language-agnostic patterns (TOCTOU, path
traversal, injection, unchecked returns, resource leaks, etc.) are in
`common.md` and always apply alongside these.

When you find an instance, report the specific variables, types, and values
involved — do not just name the pattern.

---

## 1. Integer Overflow in Allocation Size

Arithmetic on attacker-influenced values used for malloc/calloc. Overflow
wraps the result, producing an undersized buffer.

```c
// BUG: width * height * 4 can wrap to a small value
size_t total = width * height * 4;
buf = malloc(total);

// FIX: check before multiply
if (width > SIZE_MAX / height / 4) return ERROR;
size_t total = width * height * 4;
buf = malloc(total);
```

Also watch for `calloc(n, size)` — it checks internally, but code that
pre-multiplies then passes to `malloc` does not.

---

## 2. Integer Overflow in Length/Bounds Computation

Arithmetic overflow in a length or offset used for bounds checking. The
check passes because the overflowed value is small, but the actual
operation uses the original large value.

```c
// BUG: offset + len wraps, passes the < check, memcpy overflows
if (offset + len < buf_size) {
    memcpy(buf + offset, src, len);
}

// FIX: rearrange to avoid overflow
if (len > buf_size - offset) return ERROR;
```

---

## 3. Signed/Unsigned Comparison

A signed value compared to an unsigned value. Negative signed values
become large positives, bypassing bounds checks.

```c
// BUG: if len is -1, (unsigned)-1 > sizeof(buf) may not hold
//      depending on promotion rules
int len = get_length(input);
if (len > sizeof(buf)) return ERROR;
memcpy(buf, input, len);  // len cast to size_t = huge

// FIX: check negative separately
int len = get_length(input);
if (len < 0 || (size_t)len > sizeof(buf)) return ERROR;
```

---

## 4. Signed/Unsigned Conversion Truncation

Assigning a larger unsigned value to a smaller signed type, or vice
versa. The value silently truncates or reinterprets.

```c
// BUG: size_t n assigned to int — values > INT_MAX become negative
size_t n = parse_header_length(pkt);
int remaining = n;
if (remaining > 0) {
    process(buf, remaining);
}

// FIX: validate range before narrowing
if (n > INT_MAX) return ERROR;
int remaining = (int)n;
```

---

## 5. Integer Promotion in Arithmetic

C promotes `char`, `short`, `uint8_t`, `uint16_t` to `int` before
arithmetic. When the result is stored back into a narrow type, it
truncates silently.

```c
// BUG: uint16_t offset wraps at 65536, not at buffer size
uint16_t offset = 0;
while (parse_next(&offset, data)) {
    offset += field_len;   // promoted to int, truncated to uint16_t
}
buf[offset] = val;         // offset wrapped, out of bounds

// FIX: use size_t for offsets that can grow
size_t offset = 0;
```

---

## 6. Implicit Conversion in Function Arguments

Passing a signed value to a function expecting `size_t`, or a narrow
type to a function expecting a wider one, without range check.

```c
// BUG: negative read() return passed as size_t
ssize_t n = read(fd, tmp, sizeof(tmp));
memcpy(dst, tmp, n);  // n == -1 → memcpy gets SIZE_MAX

// FIX
ssize_t n = read(fd, tmp, sizeof(tmp));
if (n <= 0) return ERROR;
memcpy(dst, tmp, (size_t)n);
```

---

## 7. Off-by-One in Buffer Size

Allocating or checking `n` bytes but writing `n+1` (e.g., forgetting
the NUL terminator, or using `<=` instead of `<`).

```c
// BUG: strlen doesn't include NUL
char *copy = malloc(strlen(src));
strcpy(copy, src);  // writes strlen(src)+1 bytes

// FIX
char *copy = malloc(strlen(src) + 1);
```

Also: `for (i = 0; i <= len; i++)` iterates `len+1` times.

---

## 8. Off-by-One in Pointer Arithmetic

Calculating end-of-buffer as `buf + size` vs `buf + size - 1`, or
writing at `*end` when `end` points one past the allocation.

```c
// BUG: end is one past buffer; *p overflows
char *end = buf + buf_size;
while (p < end)
    *p++ = decode_next(&src);
*p = '\0';  // p == end, one byte past buffer

// FIX: reserve space
char *end = buf + buf_size - 1;
while (p < end)
    *p++ = decode_next(&src);
*p = '\0';
```

---

## 9. Heap Buffer Overflow via Unchecked Length

Copying more bytes than the destination holds, because a length field
from parsed data is trusted without clamping.

```c
// BUG: pkt->len is attacker-controlled
memcpy(msg.data, pkt->payload, pkt->len);

// FIX
if (pkt->len > sizeof(msg.data)) return ERROR;
memcpy(msg.data, pkt->payload, pkt->len);
```

---

## 10. Stack Buffer Overflow

Writing to a stack buffer with a length derived from external input.

```c
// BUG: unbounded sprintf
char local[256];
sprintf(local, "user=%s", name);

// FIX
int n = snprintf(local, sizeof(local), "user=%s", name);
if (n < 0 || (size_t)n >= sizeof(local)) return ERROR;
```

---

## 11. snprintf Truncation Not Checked

`snprintf` returns what *would* have been written. Using the return
value as a real length when truncation occurred reads past the buffer.

```c
// BUG: n may exceed sizeof(buf)
int n = snprintf(buf, sizeof(buf), "%s/%s", dir, file);
send(fd, buf, n);  // sends past buf if truncated

// FIX
if (n < 0 || (size_t)n >= sizeof(buf)) return ERROR;
send(fd, buf, n);
```

---

## 12. Format String

User-controlled data passed as the format argument to printf-family.

```c
// BUG
syslog(LOG_ERR, msg);
fprintf(stderr, user_input);

// FIX
syslog(LOG_ERR, "%s", msg);
fprintf(stderr, "%s", user_input);
```

`%n` writes to memory; `%s` reads arbitrary memory.

---

## 13. Use-After-Free

Accessing memory through a pointer after the allocation is freed.

```c
// BUG: item freed but still in linked list
if (validate(item) < 0) {
    free(item);
    return ERROR;  // next traversal dereferences freed memory
}

// FIX: unlink before free
if (validate(item) < 0) {
    list_remove(&list, item);
    free(item);
    return ERROR;
}
```

Also: freed pointers in caches, callbacks holding stale references,
iterator invalidation during deletion.

---

## 14. Double Free

Freeing the same allocation twice. Corrupts the heap allocator.

```c
// BUG: both error path and cleanup free p
if (parse(p) < 0) {
    free(p);
    goto cleanup;
}
cleanup:
    free(p);  // double free

// FIX: NULL after free
free(p); p = NULL;
// ... free(NULL) is safe
```

---

## 15. Null Pointer from Allocation Failure

Using the result of malloc/realloc/strdup without checking for NULL.

```c
// BUG
node = malloc(sizeof(*node));
node->next = list->head;  // crash if NULL

// FIX
node = malloc(sizeof(*node));
if (!node) return ERROR;
```

Realloc special case: on failure, returns NULL but does NOT free the
original. Overwriting the original pointer leaks it.

```c
// BUG
buf = realloc(buf, new_size);  // old buf leaked if NULL

// FIX
void *tmp = realloc(buf, new_size);
if (!tmp) { free(buf); return ERROR; }
buf = tmp;
```

---

## 16. Uninitialized Memory Read

Reading from a buffer before it is fully written. Leaks stack/heap
contents.

```c
// BUG: sends sizeof(buf), not n bytes actually read
char buf[1024];
int n = read(fd, buf, sizeof(buf));
send(client_fd, buf, sizeof(buf));

// FIX
send(client_fd, buf, n);
```

Also: structs with padding bytes sent over the wire without zeroing.

---

## 17. Incorrect sizeof

Using `sizeof(pointer)` when `sizeof(*pointer)` or `sizeof(type)` was
intended.

```c
// BUG: sizeof(ptr) is 8, not sizeof(struct record)
struct record *ptr = malloc(sizeof(ptr));

// FIX
struct record *ptr = malloc(sizeof(*ptr));
```

Also: `sizeof(array_param)` in a function — parameters are pointers.

---

## 18. Pointer Double-Scaling

Pointer arithmetic already scales by element size. Manually multiplying
by sizeof scales twice.

```c
// BUG: advances by i * sizeof(int) * sizeof(int) bytes
int *p = buf;
int *target = p + index * sizeof(int);

// FIX
int *target = p + index;
```

---

## 19. Missing NUL Terminator

`strncpy`, `memcpy`, or manual copy that doesn't guarantee NUL
termination. Subsequent string functions read past the buffer.

```c
// BUG: strncpy does NOT NUL-terminate when src >= n
strncpy(dst, src, sizeof(dst));
printf("%s", dst);

// FIX
strncpy(dst, src, sizeof(dst) - 1);
dst[sizeof(dst) - 1] = '\0';
```

---

## 20. Dangling Pointer from Realloc

`realloc` may move the allocation. Existing pointers into the old
allocation are dangling.

```c
// BUG: elem points into old allocation
struct node *elem = &array->items[3];
array->items = realloc(array->items, new_size);
elem->value = 42;  // dangling write

// FIX: re-derive after realloc
array->items = realloc(array->items, new_size);
if (!array->items) return ERROR;
elem = &array->items[3];
```

---

## 21. Signedness of char

`char` is signed on most platforms. Passing `char` to ctype functions
or using as array index produces UB for values > 127.

```c
// BUG: c may be negative
char c = buf[i];
if (isalpha(c)) { ... }

// FIX
if (isalpha((unsigned char)c)) { ... }
```

---

## 22. Misaligned Pointer Cast

Casting `char *` / `uint8_t *` to a wider type when the address may
not be aligned. UB; crashes on strict-alignment architectures.

```c
// BUG
uint32_t *val = (uint32_t *)(pkt->payload + offset);
uint32_t x = *val;

// FIX
uint32_t x;
memcpy(&x, pkt->payload + offset, sizeof(x));
```

---

## 23. Strict Aliasing Violation

Accessing the same memory through pointers of incompatible types
(other than `char *`). The compiler may optimize away the access.

```c
// BUG: compiler assumes *ip and *fp don't alias
int *ip = (int *)buf;
float *fp = (float *)buf;
*ip = 0x3f800000;
return *fp;  // may return stale value

// FIX
float result;
memcpy(&result, &bits, sizeof(result));
```

---

## 24. Shift Undefined Behaviour

Shifting by >= type width, shifting a negative value left, or shifting
into the sign bit.

```c
// BUG: n >= 32 → UB
uint32_t mask = 1 << n;

// FIX
if (n >= 32) return ERROR;
uint32_t mask = (uint32_t)1 << n;
```

---

## 25. Division / Modulo by Zero

Dividing by a value from external input that may be zero.

```c
// BUG
int ratio = total_len / avg_len;  // avg_len from parsed data

// FIX
if (avg_len == 0) return ERROR;
```

---

## 26. Incorrect Bitwise vs Logical Operator

Using `&` when `&&` was intended, or wrong operator precedence with
bitmasks.

```c
// BUG: & instead of &&
if (check_auth(user) & check_perm(resource)) { ... }

// BUG: == binds tighter than &
if (flags & MASK == VALUE) { ... }
// means: flags & (MASK == VALUE)

// FIX
if ((flags & MASK) == VALUE) { ... }
```

---

## 27. Variadic Function Type Mismatch

Wrong type passed to printf-family or other variadic functions. No
compiler check at the ABI level.

```c
// BUG: %d expects int, size_t may be 64-bit
printf("count: %d\n", num_items);

// FIX
printf("count: %zu\n", num_items);
```

Also: `NULL` must be `(void *)0` not `0` in variadic argument lists
on platforms where int and pointer sizes differ.

---

## 28. Flexible Array Member Underallocation

Allocating a struct with a trailing flexible array but not including
space for the elements.

```c
// BUG: only allocates header
struct msg { uint32_t len; char data[]; };
struct msg *m = malloc(sizeof(struct msg));
memcpy(m->data, src, n);

// FIX
struct msg *m = malloc(sizeof(struct msg) + n);
```

---

## 29. Endianness Mismatch

Using host byte order for network/file data. Silently produces wrong
values on the opposite endianness.

```c
// BUG: network byte order read as host
uint32_t len = *(uint32_t *)pkt;
buf = malloc(len);  // wildly wrong size on little-endian

// FIX
uint32_t len = ntohl(*(uint32_t *)pkt);
```

---

## 30. Macro Argument Side Effects

Macro arguments evaluated multiple times execute side effects repeatedly.

```c
// BUG: x++ evaluated twice
#define MAX(a, b) ((a) > (b) ? (a) : (b))
int largest = MAX(x++, y);

// FIX: use inline function
static inline int max_int(int a, int b) { return a > b ? a : b; }
```

Also: `assert(func_with_side_effects())` — removed in release builds.

---

## 31. Buffer Over-Read (Heartbleed-class)

Reading more bytes from a buffer than it contains, leaking adjacent
memory to the attacker.

```c
// BUG: payload_length from packet exceeds actual data
memcpy(response, payload, payload_length);
send(fd, response, payload_length);

// FIX
if (payload_length > bytes_received - header_size) return ERROR;
```

---

## 32. Free of Stack/Global Memory

Passing a stack or static buffer to `free()`.

```c
// BUG: buf may point to stack
char local[256];
char *buf = (len < 256) ? local : malloc(len);
free(buf);  // UB when buf == local

// FIX
if (buf != local) free(buf);
```

---

## 33. VLA Stack Overflow

Variable-length array with attacker-controlled size. No bounds check;
overflows the stack silently.

```c
// BUG
void process(int n) {
    char tmp[n];  // n from user
    read(fd, tmp, n);
}

// FIX
if (n > MAX_SIZE) return ERROR;
char *tmp = malloc(n);
```

---

## 34. Struct Padding Information Leak

Structs with padding bytes sent over the wire without zeroing. Padding
contains stale stack/heap data.

```c
// BUG: 3 padding bytes between type and value leaked
struct response { uint8_t type; uint32_t value; };
struct response r;
r.type = OK; r.value = result;
send(fd, &r, sizeof(r));

// FIX
memset(&r, 0, sizeof(r));
r.type = OK; r.value = result;
```

---

## 35. Signal Handler Safety

Signal handlers calling non-async-signal-safe functions or modifying
shared state without atomics.

```c
// BUG: printf not async-signal-safe; flag not volatile
int flag = 0;
void handler(int sig) {
    printf("caught\n");
    flag = 1;
}

// FIX
volatile sig_atomic_t flag = 0;
void handler(int sig) { flag = 1; }
```

---

## 36. Return of Stack Address

Returning a pointer to a local variable.

```c
// BUG
char *get_name(void) {
    char buf[256];
    snprintf(buf, sizeof(buf), "user_%d", uid);
    return buf;  // dangling
}

// FIX: heap allocate
char *get_name(void) {
    char *buf = malloc(256);
    if (!buf) return NULL;
    snprintf(buf, 256, "user_%d", uid);
    return buf;
}
```

---

## 37. Unvalidated Pointer from Cast/Offset

Casting an integer or deserialized offset to a pointer. The result may
be invalid, misaligned, or attacker-controlled.

```c
// BUG: offset from file becomes pointer
void *p = (void *)(base + header->ptr_offset);
callback(p);

// FIX
if (header->ptr_offset > buf_size - sizeof(target)) return ERROR;
```

---

## 38. Thread-Unsafe Shared State

Multiple threads accessing the same data without synchronization.
Data races are undefined in C11.

```c
// BUG
void on_request(void) { count++; }

// FIX
atomic_fetch_add(&count, 1);
```

---

## 39. Unsafe Integer Parsing (atoi / atol)

`atoi()` has no overflow detection, no error indication, and returns 0
for non-numeric input (indistinguishable from a valid "0").

```c
// BUG: no error detection; "99999999999" silently wraps; "abc" → 0
int port = atoi(user_input);
bind_to_port(port);

// FIX: strtol with full validation
char *end;
errno = 0;
long val = strtol(user_input, &end, 10);
if (errno || end == user_input || *end != '\0' ||
    val < 0 || val > 65535)
    return ERROR;
int port = (int)val;
```

Also: `sscanf("%d", ...)` has the same overflow-silently behaviour.

---

## 40. Timing Side-Channel via memcmp

Using `memcmp` to compare secrets (MACs, tokens, password hashes).
Early-exit on first differing byte leaks the correct prefix length.

```c
// BUG: early-exit reveals prefix length
if (memcmp(received_mac, expected_mac, 32) == 0) {
    accept();
}

// FIX: constant-time comparison
int diff = 0;
for (int i = 0; i < 32; i++)
    diff |= received_mac[i] ^ expected_mac[i];
if (diff == 0) accept();
```

---

## 41. Negative Offset in Pointer Arithmetic

An offset computed from attacker data that can go negative (via integer
overflow or signed/unsigned mismatch), causing the pointer to land
before the buffer start.

```c
// BUG: if base_offset overflows via multiplication, ptr lands before buf
size_t base_offset = record_index * record_size;
char *ptr = buf + base_offset;
memcpy(ptr, src, record_size);

// FIX: check multiplication overflow AND bounds
if (record_index > (buf_size / record_size)) return ERROR;
size_t base_offset = record_index * record_size;
if (base_offset + record_size > buf_size) return ERROR;
```

Also: signed index used with pointer arithmetic — a negative `int` index
on `buf[index]` reads/writes before the buffer.

---

## 42. Banned Unsafe Functions

Functions that are unconditionally dangerous regardless of usage context.
Their safe replacements should always be used.

```c
// BANNED → REPLACEMENT
gets(buf)                 → fgets(buf, sizeof(buf), stdin)
strcpy(dst, src)          → strlcpy(dst, src, sizeof(dst))   // or snprintf
strcat(dst, src)          → strlcat(dst, src, sizeof(dst))
sprintf(dst, fmt, ...)    → snprintf(dst, sizeof(dst), fmt, ...)
vsprintf(dst, fmt, va)    → vsnprintf(dst, sizeof(dst), fmt, va)
mktemp(template)          → mkstemp(template)
tmpnam(buf)               → mkstemp() or tmpfile()
```

`gets` is removed from C11. The others remain in the standard but have
no bounds checking and are the root cause of a large fraction of
historical buffer overflows.
