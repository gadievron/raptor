// Compile-only controls: unsafe functions must not be executed.
#ifdef __CODEQL_TEST__
typedef unsigned long size_t;
typedef __builtin_va_list va_list;
struct FILE;
extern "C" {
char *getenv(const char *);
char *fgets(char *, int, FILE *);
long read(int, void *, size_t);
long recv(int, void *, size_t, int);
char *strcpy(char *, const char *);
char *strdup(const char *);
int printf(const char *, ...);
int fprintf(FILE *, const char *, ...);
int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...);
int dprintf(int, const char *, ...);
int vprintf(const char *, va_list);
int vfprintf(FILE *, const char *, va_list);
int vsprintf(char *, const char *, va_list);
int vsnprintf(char *, size_t, const char *, va_list);
void syslog(int, const char *, ...);
}
#else
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <unistd.h>
#include <sys/socket.h>
#include <syslog.h>
#endif
extern "C" int printk(const char *, ...);
extern "C" void dev_err(void *, const char *, ...);
extern "C" void pr_info(const char *, ...);
namespace application {
int printf(const char *text) { return text != nullptr; }
int printk(const char *text) { return text != nullptr; }
}
struct Printer { int printf(const char *text) { return text != nullptr; } };
static const char *pass_through(const char *text) { return text; }
static void use_format(const char *format) { printf(format); }

void unsafe_env_direct(FILE *stream, char *output, va_list args) {
  printf(getenv("FORMAT"));
}
void unsafe_env_alias(FILE *stream, char *output, va_list args) {
  const char *format = getenv("FORMAT"); printf(format);
}
void unsafe_env_helper(FILE *stream, char *output, va_list args) {
  printf(pass_through(getenv("FORMAT")));
}
void unsafe_env_fprintf(FILE *stream, char *output, va_list args) {
  fprintf(stream, getenv("FORMAT"));
}
void unsafe_env_sprintf(FILE *stream, char *output, va_list args) {
  sprintf(output, getenv("FORMAT"));
}
void unsafe_env_snprintf(FILE *stream, char *output, va_list args) {
  snprintf(output, 128, getenv("FORMAT"));
}
void unsafe_env_dprintf(FILE *stream, char *output, va_list args) {
  dprintf(1, getenv("FORMAT"));
}
void unsafe_env_vprintf(FILE *stream, char *output, va_list args) {
  vprintf(getenv("FORMAT"), args);
}
void unsafe_env_vfprintf(FILE *stream, char *output, va_list args) {
  vfprintf(stream, getenv("FORMAT"), args);
}
void unsafe_env_vsprintf(FILE *stream, char *output, va_list args) {
  vsprintf(output, getenv("FORMAT"), args);
}
void unsafe_env_vsnprintf(FILE *stream, char *output, va_list args) {
  vsnprintf(output, 128, getenv("FORMAT"), args);
}
void unsafe_env_syslog(FILE *stream, char *output, va_list args) {
  syslog(3, getenv("FORMAT"));
}
void unsafe_env_printk(FILE *stream, char *output, va_list args) {
  printk(getenv("FORMAT"));
}
void unsafe_env_dev_err(FILE *stream, char *output, va_list args) {
  dev_err(nullptr, getenv("FORMAT"));
}
void unsafe_env_pr_info(FILE *stream, char *output, va_list args) {
  pr_info(getenv("FORMAT"));
}
void unsafe_read_buffer(FILE *stream, char *output, va_list args) {
  char buffer[128]; read(0, buffer, 127); printf(buffer);
}
void unsafe_recv_buffer(FILE *stream, char *output, va_list args) {
  char buffer[128]; recv(0, buffer, 127, 0); printf(buffer);
}
void unsafe_fgets_buffer(FILE *stream, char *output, va_list args) {
  char buffer[128]; fgets(buffer, 128, stream); printf(buffer);
}
void unsafe_copied_string(FILE *stream, char *output, va_list args) {
  char buffer[128]; strcpy(buffer, getenv("FORMAT")); printf(buffer);
}
void unsafe_duplicated_string(FILE *stream, char *output, va_list args) {
  printf(strdup(getenv("FORMAT")));
}
void unsafe_formatted_output(FILE *stream, char *output, va_list args) {
  snprintf(output, 128, "%s", getenv("FORMAT")); printf(output);
}
void safe_literal(FILE *stream, char *output, va_list args) {
  printf("constant");
}
void safe_env_data(FILE *stream, char *output, va_list args) {
  printf("%s", getenv("FORMAT"));
}
void safe_env_fprintf_data(FILE *stream, char *output, va_list args) {
  fprintf(stream, "%s", getenv("FORMAT"));
}
void safe_env_sprintf_data(FILE *stream, char *output, va_list args) {
  sprintf(output, "%s", getenv("FORMAT"));
}
void safe_env_snprintf_data(FILE *stream, char *output, va_list args) {
  snprintf(output, 128, "%s", getenv("FORMAT"));
}
void safe_env_syslog_data(FILE *stream, char *output, va_list args) {
  syslog(3, "%s", getenv("FORMAT"));
}
void safe_env_kernel_data(FILE *stream, char *output, va_list args) {
  dev_err(nullptr, "%s", getenv("FORMAT"));
}
void safe_reassigned_format(FILE *stream, char *output, va_list args) {
  const char *format = getenv("FORMAT"); format = "%s"; printf(format, "fixed");
}
void safe_unrelated_source(FILE *stream, char *output, va_list args) {
  const char *unused = getenv("FORMAT"); (void)unused; printf("fixed");
}
void safe_namespaced_printf(FILE *stream, char *output, va_list args) {
  application::printf(getenv("FORMAT"));
}
void safe_namespaced_printk(FILE *stream, char *output, va_list args) {
  application::printk(getenv("FORMAT"));
}
void safe_member_printf(FILE *stream, char *output, va_list args) {
  Printer printer; printer.printf(getenv("FORMAT"));
}
void safe_read_as_data(FILE *stream, char *output, va_list args) {
  char buffer[128]; read(0, buffer, 127); printf("%s", buffer);
}
void safe_constant_copy(FILE *stream, char *output, va_list args) {
  char buffer[128]; strcpy(buffer, "fixed"); printf(buffer);
}
int main(int argc, char **argv) { use_format(getenv("FORMAT")); if (argc > 1) printf(argv[1]); return 0; }
