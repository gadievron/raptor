// The standalone CodeQL test extractor uses a fixed linux_x86_64 target
// without the compiler driver's system include paths. Keep its test types
// self-contained; ordinary compiler builds below use the real system headers.
#ifdef __CODEQL_TEST__
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
#define SCHAR_MIN (-128)
#define SCHAR_MAX 127
#define UCHAR_MAX 255
#define CHAR_MIN (-128)
#define CHAR_MAX 127
#define INT_MIN (-2147483647 - 1)
#define INT_MAX 2147483647
#define INT16_MIN (-32767 - 1)
#define INT16_MAX 32767
#define UINT16_MAX 65535
#define INT32_MIN (-2147483647 - 1)
#define INT32_MAX 2147483647
#define UINT32_MAX 4294967295U
extern "C" void *malloc(unsigned long);
extern "C" void *memcpy(void *, const void *, unsigned long);
#else
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#endif
extern long long wide_signed();
extern unsigned long long wide_unsigned();
extern __int128 wide_128();
extern unsigned __int128 wide_unsigned_128();
extern int small_signed();
extern void consume_int(int);
typedef uint16_t narrow_count;
signed char unsafe_s8_raw(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  return static_cast<signed char>(value);
}
signed char unsafe_s8_weak16(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < 0 || value > 65535) return 0;
  return static_cast<signed char>(value);
}
signed char unsafe_s8_weak32(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < INT_MIN || value > INT_MAX) return 0;
  return static_cast<signed char>(value);
}
signed char unsafe_s8_upper_off_by_one(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < SCHAR_MIN || value > 128) return 0;
  return static_cast<signed char>(value);
}
signed char unsafe_s8_lower_off_by_one(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < -129 || value > SCHAR_MAX) return 0;
  return static_cast<signed char>(value);
}
signed char unsafe_s8_conditional(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (check) { if (value < SCHAR_MIN || value > SCHAR_MAX) return 0; }
  return static_cast<signed char>(value);
}
signed char unsafe_s8_reassigned(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < SCHAR_MIN || value > SCHAR_MAX) return 0;
  value = wide_signed();
  return static_cast<signed char>(value);
}
signed char unsafe_s8_arithmetic(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < 0 || value > 100) return 0;
  value *= 1000;
  return static_cast<signed char>(value);
}
signed char unsafe_s8_different_targets(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < 0 || value > 65535) return 0;
  consume_int(static_cast<int>(value));
  return static_cast<signed char>(value);
}
signed char unsafe_s8_other_guard(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (other < 0 || other > 127) return 0;
  return static_cast<signed char>(value);
}
signed char unsafe_s8_mask255(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  return static_cast<signed char>(value & 255);
}
unsigned char unsafe_u8_weak16(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  if (value > 65535) return 0;
  return static_cast<unsigned char>(value);
}
unsigned char unsafe_u8_negative(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value > UCHAR_MAX) return 0;
  return static_cast<unsigned char>(value);
}
int16_t unsafe_s16_weak32(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < INT_MIN || value > INT_MAX) return 0;
  return static_cast<int16_t>(value);
}
uint16_t unsafe_u16_weak32(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  if (value > UINT32_MAX) return 0;
  return static_cast<uint16_t>(value);
}
int32_t unsafe_s32_raw(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  return static_cast<int32_t>(value);
}
int32_t unsafe_s32_upper_only(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value > INT32_MAX) return 0;
  return static_cast<int32_t>(value);
}
uint32_t unsafe_u32_negative(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value > UINT32_MAX) return 0;
  return static_cast<uint32_t>(value);
}
uint32_t unsafe_u32_off_by_one(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  if (value > 4294967296ULL) return 0;
  return static_cast<uint32_t>(value);
}
signed char safe_s8_bounds(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < SCHAR_MIN || value > SCHAR_MAX) return 0;
  return static_cast<signed char>(value);
}
signed char safe_s8_strict(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value <= -129 || value >= 128) return 0;
  return static_cast<signed char>(value);
}
signed char safe_s8_alias(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < 0 || value > SCHAR_MAX) return 0;
  long long alias = value;
  return static_cast<signed char>(alias);
}
signed char safe_s8_mask127(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  return static_cast<signed char>(value & 127);
}
unsigned char safe_u8_bounds(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  if (value > UCHAR_MAX) return 0;
  return static_cast<unsigned char>(value);
}
unsigned char safe_u8_mask255(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  return static_cast<unsigned char>(value & 255);
}
unsigned char safe_u8_signed_source(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < 0 || value > UCHAR_MAX) return 0;
  return static_cast<unsigned char>(value);
}
int16_t safe_s16_bounds(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < INT16_MIN || value > INT16_MAX) return 0;
  return static_cast<int16_t>(value);
}
uint16_t safe_u16_bounds(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  if (value > UINT16_MAX) return 0;
  return static_cast<uint16_t>(value);
}
int32_t safe_s32_bounds(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < INT32_MIN || value > INT32_MAX) return 0;
  return static_cast<int32_t>(value);
}
uint32_t safe_u32_bounds(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  if (value > UINT32_MAX) return 0;
  return static_cast<uint32_t>(value);
}
uint32_t safe_u32_signed_source(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < 0 || value > UINT32_MAX) return 0;
  return static_cast<uint32_t>(value);
}
narrow_count safe_typedef(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < 0 || value > UINT16_MAX) return 0;
  return static_cast<narrow_count>(value);
}
char safe_plain_char(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  if (value < CHAR_MIN || value > CHAR_MAX) return 0;
  return static_cast<char>(value);
}
bool safe_bool(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  return static_cast<bool>(value);
}
long long safe_widen(bool check, int other, void *destination, const void *source) {
  int value = small_signed();
  return static_cast<long long>(value);
}
void* unsafe_memory_malloc(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  unsigned short count = static_cast<unsigned short>(value);
  return malloc(count);
}
void* unsafe_memory_memcpy(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  unsigned short count = static_cast<unsigned short>(value);
  return memcpy(destination, source, count);
}
void* safe_memory_malloc(bool check, int other, void *destination, const void *source) {
  unsigned long long value = wide_unsigned();
  if (value > UINT16_MAX) return 0;
  return malloc(static_cast<uint16_t>(value));
}
long long unsafe_i128_s64(bool check, int other, void *destination, const void *source) {
  __int128 value = wide_128();
  if (value < 0 || value > ((__int128)1 << 63)) return 0;
  return static_cast<long long>(value);
}
unsigned long long unsafe_i128_u64(bool check, int other, void *destination, const void *source) {
  unsigned __int128 value = wide_unsigned_128();
  if (value > ((unsigned __int128)1 << 64)) return 0;
  return static_cast<unsigned long long>(value);
}
long long safe_i128_s64_interior(bool check, int other, void *destination, const void *source) {
  __int128 value = wide_128();
  if (value < -100 || value > 100) return 0;
  return static_cast<long long>(value);
}
// A floating-point lower bound rounds this invalid endpoint to LLONG_MIN.
long long unsafe_i128_below_s64(bool check, int other, void *destination, const void *source) {
  __int128 value = wide_128();
  if (value < -((__int128)1 << 63) - 1 || value > 0) return 0;
  return static_cast<long long>(value);
}
void *unsafe_memory_direct_malloc(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  return malloc(static_cast<unsigned short>(value));
}
char *unsafe_memory_new_array(bool check, int other, void *destination, const void *source) {
  long long value = wide_signed();
  return new char[static_cast<unsigned short>(value)];
}
