// Standalone extractor stand-ins; real compiler builds use system headers.
#ifdef __CODEQL_TEST__
namespace std {
struct test_iterator {
  int *pointer;
  explicit test_iterator(int *p = 0) : pointer(p) { }
  int& operator*() const { return *pointer; }
  test_iterator& operator++() { ++pointer; return *this; }
  test_iterator operator++(int) { test_iterator old = *this; ++pointer; return old; }
  bool operator!=(const test_iterator& other) const { return pointer != other.pointer; }
};
#define TEST_CONTAINER(NAME) template<class T> class NAME { public: \
  typedef test_iterator iterator; NAME() { } NAME(test_iterator, test_iterator) { } \
  iterator begin() { return iterator(); } iterator end() { return iterator(); } \
  unsigned long size() const { return 3; } \
  void push_back(const T&) { } void push_front(const T&) { } \
  void clear() { } void reserve(unsigned long) { } void rehash(unsigned long) { } \
  void insert(const T&) { } iterator erase(iterator) { return iterator(); } unsigned long erase(const T&) { return 1; } iterator erase(iterator, iterator) { return iterator(); } \
  void pop_back() { } };
TEST_CONTAINER(vector)
TEST_CONTAINER(list)
TEST_CONTAINER(deque)
TEST_CONTAINER(set)
TEST_CONTAINER(unordered_set)
#undef TEST_CONTAINER
}
#else
#include <vector>
#include <list>
#include <deque>
#include <set>
#include <unordered_set>
#endif
int unsafe_vector_push(std::vector<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end(); ++it) { values.push_back(*it); }
  return 0;
}
int unsafe_vector_erase_other_capture(std::vector<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end(); ++it) { auto next = values.erase(it); (void)next; }
  return 0;
}
int unsafe_list_erase_current(std::list<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end(); ++it) { values.erase(it); }
  return 0;
}
int unsafe_list_erase_other_capture(std::list<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end(); ++it) { auto next = values.erase(it); (void)next; }
  return 0;
}
int unsafe_vector_range(std::vector<int>& values, bool flag) {
  for (int value : values) { values.push_back(value); }
  return 0;
}
int unsafe_deque_push(std::deque<int>& values, bool flag) {
  auto it = values.begin();
  values.push_back(1);
  return *it;
}
int unsafe_unordered_insert(std::unordered_set<int>& values, bool flag) {
  auto it = values.begin();
  values.insert(9);
  return *it;
}
int unsafe_unordered_rehash(std::unordered_set<int>& values, bool flag) {
  auto it = values.begin();
  values.rehash(100);
  return *it;
}
int unsafe_set_erase_key(std::set<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end(); ++it) { values.erase(*it); }
  return 0;
}
int unsafe_vector_clear(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  values.clear();
  return *it;
}
int unsafe_list_clear(std::list<int>& values, bool flag) {
  auto it = values.begin();
  values.clear();
  return *it;
}
int unsafe_list_erase_alias(std::list<int>& values, bool flag) {
  auto it = values.begin();
  auto alias = it;
  values.erase(alias);
  return *it;
}
int unsafe_cached_end(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  auto last = values.end();
  values.push_back(9);
  return it != last;
}
int unsafe_conditional_repair(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  values.push_back(9);
  if (flag) it = values.begin();
  return *it;
}
int unsafe_copy_alias(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  auto alias = it;
  values.push_back(9);
  return *alias;
}
int unsafe_clear_outside_loop(std::list<int>& values, bool flag) {
  auto it = values.begin();
  values.clear();
  ++it;
  return 0;
}
int safe_list_push(std::list<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end(); ++it) { values.push_back(1); break; }
  return 0;
}
int safe_list_insert_use(std::list<int>& values, bool flag) {
  auto it = values.begin();
  values.push_back(1);
  return *it;
}
int safe_set_insert_use(std::set<int>& values, bool flag) {
  auto it = values.begin();
  values.insert(9);
  return *it;
}
int safe_vector_return(std::vector<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end(); ++it) { values.push_back(*it); return 0; }
  return 0;
}
int safe_vector_break(std::vector<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end(); ++it) { values.push_back(*it); break; }
  return 0;
}
int safe_range_break(std::vector<int>& values, bool flag) {
  for (int value : values) { values.push_back(value); break; }
  return 0;
}
int safe_erase_assignment(std::vector<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end();) { it = values.erase(it); }
  return 0;
}
int safe_list_erase_assignment(std::list<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end();) { it = values.erase(it); }
  return 0;
}
int safe_list_erase_other(std::list<int>& values, bool flag) {
  if (values.size() < 2) return 0;
  auto it = values.begin();
  auto other = it;
  ++other;
  values.erase(other);
  return *it;
}
int safe_repair(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  values.push_back(9);
  it = values.begin();
  return *it;
}
int safe_both_repairs(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  values.push_back(9);
  if (flag) it = values.begin(); else it = values.end();
  return it != values.end();
}
int safe_fresh_iterator(std::vector<int>& values, bool flag) {
  values.push_back(9);
  auto it = values.begin();
  return *it;
}
int safe_copied_container(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  std::vector<int> copy(it, values.end());
  values.clear();
  return static_cast<int>(copy.size());
}
int unsafe_vector_erase_earlier(std::vector<int>& values, bool flag) {
  if (values.size() < 2) return 0;
  auto it = values.begin();
  ++it;
  values.erase(values.begin());
  return *it;
}
int safe_empty_erase_vector(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  values.erase(it, it);
  return *it;
}
int safe_empty_erase_list(std::list<int>& values, bool flag) {
  auto it = values.begin();
  values.erase(it, it);
  return *it;
}
int safe_list_range_insert(std::list<int>& values, bool flag) {
  for (int value : values) { values.push_front(value); }
  return 0;
}
int safe_other_container(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  std::vector<int> other;
  other.push_back(9);
  return *it;
}
int safe_rebind_other(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  std::vector<int> other;
  it = other.begin();
  values.push_back(9);
  return it != other.end();
}
int safe_unevaluated(std::vector<int>& values, bool flag) {
  auto it = values.begin();
  (void)sizeof(values.erase(it));
  return *it;
}
int safe_list_erase_postincrement(std::list<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end();) { values.erase(it++); }
  return 0;
}
int unsafe_vector_erase_postincrement(std::vector<int>& values, bool flag) {
  for (auto it = values.begin(); it != values.end();) { values.erase(it++); }
  return 0;
}
int unsafe_list_erase_prefix(std::list<int>& values, bool flag) {
  if (values.size() < 2) return 0;
  auto it = values.begin();
  values.erase(++it);
  return *it;
}
int safe_list_end_after_clear(std::list<int>& values, bool flag) {
  auto last = values.end();
  values.clear();
  return last != values.end();
}
