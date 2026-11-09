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

C11 review lead: establish actual target types/ranges, not host widths.
Unsigned arithmetic wraps; signed overflow is undefined behaviour. A
destination type does not widen the earlier expression. Check other
language editions separately.

```c
// LEAD: multiplication may overflow before allocation
size_t total = width * height * 4;
buf = malloc(total);

// CHECK: width and height are validated size_t values
if (height != 0 && width > SIZE_MAX / height) return ERROR;
size_t pixels = width * height;
if (pixels > SIZE_MAX / 4) return ERROR;
size_t total = pixels * 4;
buf = malloc(total);
```

Also check the identified `calloc` implementation and its failure handling;
a product computed before the call has already lost overflow information.

---

## 2. Integer Overflow in Length/Bounds Computation

A wrapped unsigned length or offset can defeat a bounds check. Signed
overflow is undefined behaviour, not portable wrapping. Check actual extents.

```c
// LEAD: size_t offset + len may wrap before the comparison
if (offset + len < buf_size) memcpy(buf + offset, src, len);

// CHECK: size_t values; reject before subtraction can underflow
if (offset > buf_size || len > buf_size - offset) return ERROR;
```

This checks the destination range only; the source range still needs review.

---

## 3. Signed/Unsigned Comparison

Apply promoted operand ranks/ranges. A negative-to-unsigned conversion
becomes large; comparison direction determines whether it defeats a check.

```c
// LEAD: same-rank mixed operands; available == -1 becomes UINT_MAX
int available = get_available();  // negative on failure
unsigned int requested = parse_count(input);
if (requested > available) return ERROR;
memcpy(dst, src, requested);

// CHECK: reject the error before converting; verify actual buffer extents too
if (available < 0 || requested > (unsigned int)available) return ERROR;
```

Do not assume `int len = -1; len > sizeof(buf)` bypasses rejection: where
`len` converts to size_t, the resulting large value normally rejects it.

---

## 4. Signed/Unsigned Conversion Truncation

In C11, out-of-range signed integer conversion has an implementation-defined result or signal.
Representable integer values are unchanged; other unsigned destinations
reduce modulo their range. `_Bool` instead converts zero to zero and other
scalar values to one.

```c
// LEAD: n may not fit int; do not assume it necessarily becomes negative
size_t n = parse_header_length(pkt);
int remaining = n;
process(buf, remaining);

// CHECK: reject before narrowing, then verify process's buffer contract
if (n > INT_MAX) return ERROR;
int remaining = (int)n;
```

Show a reachable out-of-range value and harmful use; a cast alone is not a defect.

---

## 5. Integer Promotion in Arithmetic

Integer promotions depend on the original type's range and rank.
Eligible operands become int only if it holds all values, otherwise
unsigned int. uint16_t need not promote to int.
Apply the operator's rules; a wider assignment does not fix earlier overflow.

```c
// LEAD: compound assignment converts the result back to uint16_t
uint16_t offset = base;
offset += field_len;
```

If arithmetic is defined, conversion back to uint16_t reduces modulo
65536. Wrapping is not automatically out of bounds. size_t alone is no
fix: check `offset <= buf_size` and `field_len <= buf_size - offset`
before adding validated size_t values.

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

Plain char signedness is implementation-defined; ctype arguments have a restricted domain.
Ctype requires EOF or a value representable as unsigned char; other arguments have
undefined behaviour. A negative array index needs its own bounds analysis.

```c
char c = buf[i];
// LEAD: a negative c other than EOF is outside isalpha's domain
if (isalpha(c)) { ... }

// CHECK: byte held in char, on a target with UCHAR_MAX <= INT_MAX
if (isalpha((unsigned char)c)) { ... }
```

For an int returned by fgetc, preserve and check EOF before converting.

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

In C11, shift counts must be nonnegative and below the promoted left operand's width.
Other counts are undefined. Signed left shift also requires a nonnegative
left operand and a representable result. Negative signed right shift is
implementation-defined. The destination width does not set the shift width.

```c
// LEAD: 1 has type int; n == 31 may already fail on a 32-bit int
uint32_t mask = 1 << n;

// CHECK: n is unsigned; form a 32-bit mask using an unsigned wide operand
if (n >= 32) return ERROR;
uint32_t mask = (uint32_t)(1ULL << n);
```

The checked form assumes uint32_t exists; a signed count also needs n >= 0.

---

## 25. Division / Modulo by Zero

C11 division/remainder is undefined for zero divisors or unrepresentable quotients.
INT_MIN / -1 and INT_MIN % -1 fail only on asymmetric int ranges.

```c
// CHECK: total_len and avg_len are int
if (avg_len == 0 || (total_len < -INT_MAX && avg_len == -1)) return ERROR;
int ratio = total_len / avg_len;
```

Use the actual promoted operand type and its limits for other integer types.

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

C11 atoi/atol lack reliable error reporting; an unrepresentable result is undefined.
Do not assume silent wrapping. No conversion
can also return zero. Check the entire accepted input and destination range.

```c
// LEAD: malformed or out-of-range input is not diagnosed
int port = atoi(user_input);

// CHECK: strtol conversion and application range (unsigned int holds 65535)
char *end;
errno = 0;
long val = strtol(user_input, &end, 10);
if (errno || end == user_input || *end != '\0' ||
    val < 0 || val > 65535)
    return ERROR;
unsigned int port = (unsigned int)val;
```

For scanf-family numeric conversion, an unrepresentable destination result
also has undefined behaviour; field width alone is not a range check.

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

A negative index or wrapped unsigned offset can select the wrong buffer position.
size_t operands may promote to signed int: signed overflow is undefined. If evaluated unsigned, a
product wraps to a nonnegative value, potentially selecting the wrong record.

```c
// LEAD: size_t product may wrap, losing the intended record position
size_t base_offset = record_index * record_size;
memcpy(buf + base_offset, src, record_size);

// CHECK: validated size_t values; reject zero and require one whole record
if (record_size == 0 || record_size > buf_size) return ERROR;
if (record_index > (buf_size - record_size) / record_size) return ERROR;
size_t base_offset = record_index * record_size;
```

The product and destination fit; check source extent separately. Zero-sized
records need an explicit policy, not division by zero.

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
