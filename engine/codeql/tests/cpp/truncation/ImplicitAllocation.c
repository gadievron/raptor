#ifdef __CODEQL_TEST__
typedef unsigned long size_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
#define UINT32_MAX 4294967295U
#else
#include <stddef.h>
#include <stdint.h>
#endif
extern void *malloc(size_t);
extern void *calloc(size_t, size_t);
extern void *realloc(void *, size_t);
extern void *vmalloc(size_t);
extern void *kmalloc(size_t, unsigned int);
extern void *kzalloc(size_t, unsigned int);
extern void *kmalloc_array(size_t, size_t, unsigned int);
extern void *kcalloc(size_t, size_t, unsigned int);
extern unsigned long wide_count(void);
extern void consume(unsigned int);
#define ROUND_UP(n, sz) ((((n) + (sz) - 1) / (sz)) * (sz))

void *allocation_assignment(unsigned long wide) {
  unsigned int count;
  count = wide;
  return malloc(count);
}
void *allocation_initializer(unsigned long wide) {
  uint16_t count = wide;
  return calloc(count, 8);
}
void *allocation_bitmap(unsigned long wide) {
  unsigned int count = wide;
  size_t bytes = ROUND_UP(count, 64);
  bytes >>= 3;
  return vmalloc(bytes);
}
void *allocation_statement_expression(unsigned long wide, unsigned int divisor) {
  unsigned int count = ({ unsigned long r = wide / divisor; r; });
  size_t bytes = ROUND_UP(count, 64);
  bytes >>= 3;
  return vmalloc(bytes);
}
void *allocation_call(void) {
  unsigned int count = wide_count();
  return kmalloc(count * 8UL, 0);
}
void *allocation_alias(unsigned long wide) {
  unsigned int count = wide;
  size_t alias = count;
  return kzalloc(alias + 8, 0);
}
void *allocation_signed(long wide) {
  short count = wide;
  return malloc(count);
}
void *allocation_realloc(void *old, unsigned long wide) {
  uint32_t count = wide;
  return realloc(old, count);
}
void *allocation_array(unsigned long wide) {
  uint32_t count = wide;
  return kmalloc_array(count, 4, 0);
}
void *allocation_second_factor(unsigned long wide) {
  uint32_t count = wide;
  return kcalloc(4, count, 0);
}
void *allocation_guarded(unsigned long wide) {
  if (wide > UINT32_MAX) return 0;
  unsigned int count = wide;
  return malloc(count);
}
void *allocation_guarded_signed(long wide) {
  if (wide < 0 || wide > 65535) return 0;
  uint16_t count = wide;
  return malloc(count);
}
void *allocation_negative(long wide) {
  if (wide > 65535) return 0;
  uint16_t count = wide;
  return malloc(count);
}
void *allocation_off_by_one(unsigned long wide) {
  if (wide > 4294967296UL) return 0;
  unsigned int count = wide;
  return malloc(count);
}
void *allocation_postconversion_guard(unsigned long wide) {
  unsigned int count = wide;
  if (count > 65535) return 0;
  return malloc(count);
}
void *allocation_widened(unsigned long wide) {
  size_t count = wide;
  return malloc(count);
}
void *allocation_overwritten(unsigned long wide) {
  unsigned int count = wide;
  consume(count);
  count = 8;
  return malloc(count);
}
void *allocation_unrelated(unsigned long wide) {
  unsigned int count = wide;
  consume(count);
  return malloc(8);
}
void *allocation_wrong_argument(unsigned long wide) {
  unsigned int flags = wide;
  return kmalloc(8, flags);
}
void *allocation_masked(unsigned long wide) {
  uint16_t count = wide & 65535;
  return malloc(count);
}
void *allocation_guard_then_arithmetic(unsigned long wide) {
  if (wide > UINT32_MAX) return 0;
  unsigned int count = wide + 1;
  return malloc(count);
}
void *allocation_explicit(unsigned long wide) {
  unsigned int count = (unsigned int)wide;
  return malloc(count);
}
void *allocation_bool(unsigned long wide) {
  _Bool count = wide;
  return malloc(count);
}
void *allocation_pointer(void *pointer) {
  return malloc((unsigned long)pointer);
}
void *allocation_no_sink(unsigned long wide) {
  unsigned int count = wide;
  consume(count);
  return 0;
}
void *allocation_returned(unsigned long wide) {
  return malloc(({ unsigned int count = wide; count; }));
}

// Match the preprocessed kernel allocation hook and statement expression.
extern void *vmalloc_noprof(unsigned long);
#define kernel_vmalloc(...) ({ void *result = vmalloc_noprof(__VA_ARGS__); result; })
void *allocation_profiled_bitmap(unsigned long wide, unsigned int divisor) {
  unsigned int count = ({ unsigned long r = wide / divisor; r; });
  size_t bytes = ROUND_UP(count, 64);
  bytes >>= 3;
  return kernel_vmalloc(bytes);
}
void *allocation_profiled_guarded(unsigned long wide) {
  if (wide > UINT32_MAX) return 0;
  unsigned int count = wide;
  return kernel_vmalloc(count);
}

struct allocation_key { unsigned int bits; };
struct allocation_tag { unsigned short length, type; };
#define TAG_ALIGN(n) (((n) + 4U - 1) & ~(4U - 1))
#define TAG_SPACE(n) TAG_ALIGN(TAG_ALIGN(sizeof(struct allocation_tag)) + (n))
void *allocation_bounded_promotion(struct allocation_key *auth,
                                   struct allocation_key *encryption) {
  unsigned int count = (auth ? (auth->bits + 7) / 8 : 0) +
                      (encryption->bits + 7) / 8 + TAG_SPACE(sizeof(unsigned int));
  return malloc(count);
}
void *allocation_bounded_promotion_bad_add(struct allocation_key *key) {
  unsigned int count = (key->bits + 7) / 8 + 4294967295UL;
  return malloc(count);
}
void *allocation_bounded_promotion_wide_arm(unsigned long wide,
                                          struct allocation_key *key, int flag) {
  unsigned int count = flag ? wide : (key->bits + 7) / 8 + sizeof(unsigned int);
  return malloc(count);
}
void *allocation_bounded_promotion_no_div(struct allocation_key *key) {
  unsigned int count = key->bits + sizeof(unsigned int);
  return malloc(count);
}
void *allocation_bounded_promotion_signed(long wide) {
  unsigned int count = wide / 8 + sizeof(unsigned int);
  return malloc(count);
}
void *allocation_variable_divisor(unsigned int bits, unsigned long divisor) {
  if (!divisor) return 0;
  uint16_t count = (unsigned long)bits / divisor;
  return malloc(count);
}
