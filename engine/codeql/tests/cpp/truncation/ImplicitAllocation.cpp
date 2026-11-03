#ifdef __CODEQL_TEST__
typedef unsigned long size_t;
#else
#include <stddef.h>
#endif
extern void *malloc(size_t);
unsigned char *allocation_cpp_array(unsigned long wide) {
  unsigned int count = wide;
  return new unsigned char[count];
}
unsigned char *allocation_cpp_guarded(unsigned long wide) {
  if (wide > 4294967295UL) return nullptr;
  unsigned int count = wide;
  return new unsigned char[count];
}
namespace unrelated {
  void *malloc(unsigned long);
  void *vmalloc_noprof(unsigned long);
}
void *allocation_cpp_shadow(unsigned long wide) {
  unsigned int count = wide;
  return unrelated::malloc(count);
}
void *allocation_cpp_profiled_shadow(unsigned long wide) {
  unsigned int count = wide;
  return unrelated::vmalloc_noprof(count);
}
