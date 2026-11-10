// Standalone extractor fixtures; real compiler builds use system headers.
#ifdef __CODEQL_TEST__
namespace std {
    template<class T> T&& move(T& value) { return static_cast<T&&>(value); }
    template<class T> class unique_ptr {
        T *pointer;
    public:
        explicit unique_ptr(T *value = 0) : pointer(value) { }
        unique_ptr(unique_ptr&& other) : pointer(other.pointer) { other.pointer = 0; }
        unique_ptr& operator=(unique_ptr&& other) { pointer = other.pointer; other.pointer = 0; return *this; }
        unique_ptr(const unique_ptr&) = delete;
        unique_ptr& operator=(const unique_ptr&) = delete;
        ~unique_ptr() { }
        T& operator*() const { return *pointer; }
        void reset(T *value = 0) { pointer = value; }
        T *get() const { return pointer; }
        void swap(unique_ptr& other) { T *old = pointer; pointer = other.pointer; other.pointer = old; }
        explicit operator bool() const { return pointer != 0; }
    };
    template<class T> class vector {
    public:
        vector() { }
        vector(vector&&) { }
        void push_back(T&& value) { T consumed(std::move(value)); }
        struct iterator { };
        iterator begin() { return iterator(); }
        void insert(iterator, T&& value) { T consumed(std::move(value)); }
        unsigned long size() const { return 0; }
        bool empty() const { return true; }
    };
    template<class T> class list {
    public:
        void push_front(T&& value) { T consumed(std::move(value)); }
    };
}
#else
#include <utility>
#include <memory>
#include <vector>
#include <list>
#endif

typedef std::unique_ptr<int> Pointer;
extern void take(Pointer);
static void inspect_const(const Pointer&) { }
static void inspect_rvalue(Pointer&&) { }
extern void take_vector(std::vector<int>);
struct Copyable {
    int *pointer;
    explicit Copyable(int *p) : pointer(p) { }
    Copyable(const Copyable& other) : pointer(other.pointer) { }
    Copyable(Copyable&& other) : pointer(other.pointer) { other.pointer = 0; }
    int read() const { return *pointer; }
    void reset() { }
};
extern void take_copyable(Copyable);
struct Plain { int value; };
extern void take_plain(Plain);
int unsafe_consumed(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    return *value;
}
int unsafe_move_constructed(bool flag) {
    Pointer value(new int(7));
    Pointer destination(std::move(value));
    return *value;
}
int unsafe_move_assigned(bool flag) {
    Pointer value(new int(7));
    Pointer destination;
    destination = std::move(value);
    return *value;
}
int unsafe_conditional_assignment(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    if (flag) value = Pointer(new int(8));
    return *value;
}
int unsafe_conditional_reset(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    if (flag) value.reset(new int(8));
    return *value;
}
int unsafe_conditional_move(bool flag) {
    Pointer value(new int(7));
    if (flag) take(std::move(value));
    return *value;
}
int unsafe_reset_other_branch(bool flag) {
    Pointer value(new int(7));
    Pointer other(new int(9));
    take(std::move(value));
    if (flag) other = Pointer(new int(8));
    return *value;
}
int unsafe_reset_before_move(bool flag) {
    Pointer value(new int(7));
    value = Pointer(new int(8));
    take(std::move(value));
    return *value;
}
int unsafe_reset_after_use(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    int result = *value;
    value = Pointer(new int(8));
    return result;
}
int unsafe_one_branch_reset(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    if (flag) value = Pointer(new int(8)); else { int marker = 0; (void)marker; }
    return *value;
}
int unsafe_self_move(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    value = std::move(value);
    return *value;
}
int unsafe_rhs_uses_old(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    value = Pointer(new int(*value));
    return *value;
}
int unsafe_loop_carried(bool flag) {
    Pointer value(new int(7));
    int result = 0;
    for (int i = 0; i < 2; ++i) { result += *value; take(std::move(value)); }
    return result;
}
int unsafe_loop_maybe_reset(bool flag) {
    Pointer value(new int(7));
    for (int i = 0; i < 2; ++i) { take(std::move(value)); if (flag) value = Pointer(new int(8)); }
    return *value;
}
int unsafe_push_back(bool flag) {
    Pointer value(new int(7));
    std::vector<Pointer> values;
    values.push_back(std::move(value));
    return *value;
}
int unsafe_push_front(bool flag) {
    Pointer value(new int(7));
    std::list<Pointer> values;
    values.push_front(std::move(value));
    return *value;
}
int unsafe_insert(bool flag) {
    Pointer value(new int(7));
    std::vector<Pointer> values;
    values.insert(values.begin(), std::move(value));
    return *value;
}
int unsafe_discarded_destination(bool flag) {
    Pointer value(new int(7));
    (void)Pointer(std::move(value));
    return *value;
}
int unsafe_same_line(bool flag) {
    Pointer value(new int(7)); take(std::move(value)); return *value;
}
int safe_same_line_reset(bool flag) {
    Pointer value(new int(7)); take(std::move(value)); value = Pointer(new int(8)); return *value;
}
int safe_unevaluated(bool flag) {
    Pointer value(new int(7));
    (void)sizeof(Pointer(std::move(value)));
    return *value;
}
int safe_unreachable_move(bool flag) {
    Pointer value(new int(7));
    return *value;
    take(std::move(value));
    return *value;
}
int unsafe_custom_reset(bool flag) {
    int x = 7;
    Copyable value(&x);
    take_copyable(std::move(value));
    value.reset();
    return value.read();
}
int safe_discarded(bool flag) {
    Pointer value(new int(7));
    std::move(value);
    return *value;
}
int safe_void_discarded(bool flag) {
    Pointer value(new int(7));
    (void)std::move(value);
    return *value;
}
int safe_reference_bound(bool flag) {
    Pointer value(new int(7));
    Pointer&& alias = std::move(value);
    (void)alias;
    return *value;
}
int safe_const_reference(bool flag) {
    Pointer value(new int(7));
    inspect_const(std::move(value));
    return *value;
}
int safe_observing_rvalue(bool flag) {
    Pointer value(new int(7));
    inspect_rvalue(std::move(value));
    return *value;
}
int safe_copy_from_const(bool flag) {
    int x = 7;
    const Copyable value(&x);
    take_copyable(std::move(value));
    return value.read();
}
int safe_scalar(bool flag) {
    int value = 7;
    int destination = std::move(value);
    return value + destination;
}
int safe_scalar_insertion(bool flag) {
    int value = 7;
    std::vector<int> values;
    values.push_back(std::move(value));
    return value;
}
int safe_plain_value(bool flag) {
    Plain value = {7};
    take_plain(std::move(value));
    return value.value;
}
int safe_plain_insertion(bool flag) {
    Plain value = {7};
    std::vector<Plain> values;
    values.push_back(std::move(value));
    return value.value;
}
int safe_assignment(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    value = Pointer(new int(8));
    return *value;
}
int safe_reset(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    value.reset(new int(8));
    return *value;
}
int safe_swap(bool flag) {
    Pointer value(new int(7));
    Pointer other(new int(8));
    take(std::move(value));
    value.swap(other);
    return *value;
}
int unsafe_conditional_swap(bool flag) {
    Pointer value(new int(7));
    Pointer other(new int(8));
    take(std::move(value));
    if (flag) value.swap(other);
    return *value;
}
int safe_reset_both_branches(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    if (flag) value = Pointer(new int(8)); else value = Pointer(new int(9));
    return *value;
}
int safe_reset_and_return(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    if (flag) value = Pointer(new int(8)); else return 0;
    return *value;
}
int safe_disjoint_branch(bool flag) {
    Pointer value(new int(7));
    if (flag) { take(std::move(value)); return 0; }
    return *value;
}
int safe_use_before_move(bool flag) {
    Pointer value(new int(7));
    int result = *value;
    take(std::move(value));
    return result;
}
int safe_move_then_return(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    return 0;
}
int safe_loop_reset(bool flag) {
    Pointer value(new int(7));
    for (int i = 0; i < 2; ++i) { take(std::move(value)); value = Pointer(new int(8)); }
    return *value;
}
int safe_size_observation(bool flag) {
    std::vector<int> value;
    take_vector(std::move(value));
    return static_cast<int>(value.size());
}
int safe_bool_observation(bool flag) {
    Pointer value(new int(7));
    take(std::move(value));
    return static_cast<bool>(value) ? 1 : 0;
}
int safe_other_variable(bool flag) {
    Pointer value(new int(7));
    Pointer other(new int(9));
    take(std::move(value));
    return *other;
}

int safe_get_null_observation() {
    Pointer value(new int(7));
    Pointer destination(std::move(value));
    return value.get() == nullptr;
}
int safe_get_null_observation_reversed() {
    Pointer value(new int(7));
    Pointer destination(std::move(value));
    return nullptr != value.get();
}
int safe_get_null_without_move() {
    Pointer value(new int(7));
    return value.get() == nullptr;
}
int unsafe_get_dereference() {
    Pointer value(new int(7));
    Pointer destination(std::move(value));
    return *value.get();
}
struct OtherPointer {
    int *pointer;
    explicit OtherPointer(int *value) : pointer(value) { }
    OtherPointer(OtherPointer&& other) : pointer(other.pointer) { other.pointer = 0; }
    int *get() const { return *pointer ? pointer : nullptr; }
};
int unsafe_custom_get_null() {
    OtherPointer value(new int(7));
    OtherPointer destination(std::move(value));
    return value.get() == nullptr;
}
