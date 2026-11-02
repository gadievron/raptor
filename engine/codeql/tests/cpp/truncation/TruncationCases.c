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
#else
#include <stdint.h>
#include <limits.h>
#endif
extern long long c_wide(void);
signed char unsafe_c_s8(void) {
  long long value = c_wide();
  if (value < 0 || value > 65535) return 0;
  return (signed char)value;
}
signed char safe_c_s8(void) {
  long long value = c_wide();
  if (value < SCHAR_MIN || value > SCHAR_MAX) return 0;
  return (signed char)value;
}
uint16_t unsafe_c_u16(void) {
  long long value = c_wide();
  if (value > UINT16_MAX) return 0;
  return (uint16_t)value;
}
uint16_t safe_c_u16(void) {
  long long value = c_wide();
  if (value < 0 || value > UINT16_MAX) return 0;
  return (uint16_t)value;
}
