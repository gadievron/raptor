# Go Vulnerability Patterns

Go-specific patterns. Language-agnostic patterns (injection, TOCTOU,
path traversal, etc.) are in `common.md` and always apply alongside
these.

---

## 1. Ignored Error Return

Go functions return errors as values. Ignoring them silently continues
with zero-value or corrupt state.

```go
// BUG: err not checked — data may be zero-length/invalid
data, _ := ioutil.ReadAll(resp.Body)
json.Unmarshal(data, &config)

// FIX
data, err := ioutil.ReadAll(resp.Body)
if err != nil { return fmt.Errorf("read body: %w", err) }
if err := json.Unmarshal(data, &config); err != nil {
    return fmt.Errorf("parse config: %w", err)
}
```

Common pattern: `err` assigned but never checked, especially after
the last call in a function.

---

## 2. Integer Truncation on Cast

Go does not error on narrowing integer conversions. Casting a large
value to a smaller type silently truncates.

```go
// BUG: if count > math.MaxInt32, result wraps
count := getUint64FromHeader(pkt)
n := int32(count)
buf := make([]byte, n)  // undersized or negative-length

// FIX
if count > math.MaxInt32 { return ErrTooLarge }
n := int32(count)
```

Also: `int` is 64-bit on 64-bit platforms but 32-bit on 32-bit.
Code that casts `int64` → `int` silently truncates on 32-bit builds.

---

## 3. Goroutine Leak

Starting a goroutine that blocks forever (on channel, mutex, I/O)
when no one will ever unblock it.

```go
// BUG: if ctx is cancelled, this goroutine blocks on ch forever
go func() {
    result := expensiveComputation()
    ch <- result  // blocks if no one reads ch
}()

// FIX: select with context
go func() {
    result := expensiveComputation()
    select {
    case ch <- result:
    case <-ctx.Done():
    }
}()
```

---

## 4. Race Condition on Shared State

Concurrent goroutines accessing shared variables without
synchronization. Go's race detector catches these at runtime, but
only on exercised paths.

```go
// BUG: data race on count
var count int
go func() { count++ }()
go func() { count++ }()

// FIX: use atomic or mutex
var count atomic.Int64
go func() { count.Add(1) }()
```

---

## 5. Slice Header Aliasing

Slices share underlying arrays. Appending to a sub-slice may overwrite
elements in the parent, or not (depending on capacity). Both cases
cause bugs.

```go
// BUG: a and b share underlying array; append to a may overwrite b
a := data[:3]
b := data[3:]
a = append(a, newElement)  // if cap(data) > 3, overwrites b[0]

// FIX: force a copy
a := append([]byte{}, data[:3]...)
```

---

## 6. Nil Interface vs Nil Pointer

An interface holding a nil pointer is not nil. Nil checks fail
unexpectedly.

```go
// BUG: err is non-nil (holds typed nil *MyError)
func getError() error {
    var err *MyError
    return err  // interface{type: *MyError, value: nil} != nil
}
if err := getError(); err != nil {
    // enters this branch even though the pointer is nil
}

// FIX: return nil explicitly
func getError() error {
    return nil
}
```

---

## 7. defer in Loop

`defer` runs at function exit, not loop iteration exit. Resources
opened in a loop accumulate until the function returns.

```go
// BUG: all files open simultaneously until function returns
for _, path := range files {
    f, _ := os.Open(path)
    defer f.Close()  // deferred until function exit
    process(f)
}

// FIX: use a closure or explicit close
for _, path := range files {
    func() {
        f, _ := os.Open(path)
        defer f.Close()
        process(f)
    }()
}
```

---

## 8. Loop Variable Capture (pre-Go 1.22)

In Go < 1.22, loop variables are captured by reference in closures
and goroutines. All iterations share the same variable.

```go
// BUG (Go < 1.22): all goroutines see the last value of i
for i, val := range items {
    go func() {
        process(i, val)  // i and val are the loop variable
    }()
}

// FIX: copy to local
for i, val := range items {
    i, val := i, val
    go func() {
        process(i, val)
    }()
}
```

Go 1.22+ changed this behaviour, but code targeting older versions
or using `for i = 0; i < n; i++` style is still vulnerable.

---

## 9. Unbuffered Channel Deadlock

Sending on an unbuffered channel blocks until a receiver is ready.
If the receiver exits or is never started, the sender deadlocks.

```go
// BUG: if process() returns early, sender blocks forever
ch := make(chan int)
go func() { ch <- compute() }()
if err := process(); err != nil {
    return err  // goroutine blocked on ch forever
}
result := <-ch
```

---

## 10. HTTP Handler Concurrency

HTTP handlers in `net/http` run concurrently. Shared state accessed
from handlers without synchronization is a data race.

```go
// BUG: concurrent map write
var cache = map[string]string{}
func handler(w http.ResponseWriter, r *http.Request) {
    cache[r.URL.Path] = result  // concurrent map write → panic
}

// FIX: sync.Map or mutex
var cache sync.Map
```

---

## 11. Path Traversal via filepath.Join

`filepath.Join` cleans the path but does NOT prevent traversal.
`../` sequences in the user component can escape the base directory.

```go
// BUG: userPath = "../../etc/passwd"
path := filepath.Join(baseDir, userPath)

// FIX: resolve and check containment
path := filepath.Join(baseDir, filepath.Clean("/"+userPath))
abs, _ := filepath.Abs(path)
if !strings.HasPrefix(abs, filepath.Clean(baseDir)+string(os.PathSeparator)) {
    return ErrTraversal
}
```

---

## 12. Unsafe Package Use

`unsafe.Pointer` conversions bypass the type system. Incorrect use
causes memory corruption, use-after-GC, or alignment violations.

```go
// BUG: p may be moved by GC between conversion and use
p := unsafe.Pointer(&obj.field)
uintptrVal := uintptr(p)
// GC may move obj here
ptr := (*int)(unsafe.Pointer(uintptrVal))  // dangling

// FIX: single expression, no uintptr intermediate
ptr := (*int)(unsafe.Pointer(&obj.field))
```

---

## 13. sql.ErrNoRows Not Handled

`sql.QueryRow().Scan()` returns `sql.ErrNoRows` when no row matches.
Treating this as a fatal error or ignoring it causes incorrect
behaviour on missing data.

```go
// BUG: returns error for legitimate "not found" case
err := db.QueryRow("SELECT ...").Scan(&val)
if err != nil {
    return err  // ErrNoRows treated as fatal
}

// FIX
err := db.QueryRow("SELECT ...").Scan(&val)
if errors.Is(err, sql.ErrNoRows) {
    return nil, nil  // not found is OK
}
if err != nil {
    return nil, err
}
```

---

## 14. Context Cancellation Leak

Not propagating context cancellation to long-running operations. The
operation continues wasting resources after the caller has given up.

```go
// BUG: HTTP request ignores context cancellation
resp, err := http.Get(url)  // blocks even if ctx is cancelled

// FIX: use request with context
req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
resp, err := http.DefaultClient.Do(req)
```

---

## 15. Panic in Goroutine

An unrecovered panic in a goroutine crashes the entire process. Library
code that spawns goroutines must recover.

```go
// BUG: panic in worker crashes the whole server
go func() {
    process(item)  // may panic
}()

// FIX: recover in the goroutine
go func() {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("worker panic: %v", r)
        }
    }()
    process(item)
}()
```

---

## 16. HTTP Response Body Not Closed

`http.Client.Do` / `http.Get` returns a body that MUST be closed, even
on error paths. Unclosed bodies leak TCP connections; the transport
eventually runs out of connections (DoS to self).

```go
// BUG: body not closed on early return
resp, err := http.Get(url)
if err != nil { return err }
if resp.StatusCode != 200 {
    return fmt.Errorf("bad status: %d", resp.StatusCode)
    // resp.Body leaked
}

// FIX: defer close immediately after nil check
resp, err := http.Get(url)
if err != nil { return err }
defer resp.Body.Close()
```
