# Common Vulnerability Patterns (Language-Agnostic)

These patterns apply across languages. Examples use C or pseudocode for
clarity; the shapes exist in every language with appropriate syntax.

---

## 1. Unchecked Return Value

Using the result of a fallible operation without verifying success.
Subsequent code operates on stale, default, or undefined state.

```c
// BUG: read may fail or return short
read(fd, buf, 4);
uint32_t len = *(uint32_t *)buf;  // buf may be stale

// FIX
if (read(fd, buf, 4) != 4) return ERROR;
```

Applies to: file I/O, network recv/send, memory allocation, parsing,
database queries, HTTP requests — any call that can fail.

---

## 2. TOCTOU (Time-of-Check to Time-of-Use)

Checking a condition and then acting on it in a separate operation.
The state may change between the two steps.

```c
// BUG: file replaced between stat() and open()
if (stat(path, &st) == 0 && st.st_size < MAX) {
    fd = open(path, O_RDONLY);  // different file
}

// FIX: open first, then check via the fd
fd = open(path, O_RDONLY);
if (fd < 0) return ERROR;
fstat(fd, &st);
if (st.st_size >= MAX) { close(fd); return ERROR; }
```

Applies to: file access, permission checks, lock-then-act, database
read-then-write, cache check-then-use.

---

## 3. Path Traversal

User input concatenated into a file path without sanitizing directory
traversal sequences. Attacker escapes the intended directory.

```c
// BUG: name = "../../etc/passwd"
snprintf(path, sizeof(path), "%s/%s", base_dir, name);
fd = open(path, O_RDONLY);

// FIX: resolve and verify containment
realpath(path, resolved);
if (strncmp(resolved, base_dir, strlen(base_dir)) != 0) return ERROR;
```

Also applies in Python (`os.path.join` does NOT prevent traversal),
Java, Go, etc. Watch for URL-encoded traversal (`%2e%2e%2f`), null
bytes truncating the path, and symlink following.

---

## 4. Command Injection

User data interpolated into a command string. Shell metacharacters
(`;`, `|`, `$()`, backticks, newlines) execute arbitrary commands.

```c
// BUG
snprintf(cmd, sizeof(cmd), "convert %s out.png", filename);
system(cmd);

// FIX: use exec with argv array, never shell
char *argv[] = {"convert", filename, "out.png", NULL};
execve("/usr/bin/convert", argv, envp);
```

Dangerous APIs across languages:
- C: `system()`, `popen()`, `execl()` with shell
- Python: `os.system()`, `os.popen()`, `subprocess.run(shell=True)`
- Go: `exec.Command("sh", "-c", userInput)`
- Java: `Runtime.exec(cmd)` (splits on whitespace, not shell — different bug)
- JS: `child_process.exec()` (shell), vs `execFile()` (no shell)

The fix is always: argv array, never shell string.

---

## 5. Unsanitised Environment

The process environment is attacker-controlled in many contexts (CGI,
setuid, containers, CI runners, shared hosting). Trusting `getenv()`
without validation, or passing the inherited environment to child
processes, enables privilege escalation and code injection without
touching the command string.

Dangerous environment variables:
- **Loader hijack**: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`,
  `PYTHONPATH`, `PYTHONSTARTUP`, `NODE_OPTIONS`, `NODE_PATH`, `RUBYLIB`,
  `PERL5LIB`, `CLASSPATH`, `JAVA_TOOL_OPTIONS`
- **Execution redirect**: `PATH`, `SHELL`, `EDITOR`, `VISUAL`, `PAGER`,
  `BROWSER`, `TERMINAL`, `GIT_SSH_COMMAND`
- **Behaviour override**: `IFS`, `TMPDIR`, `HOME`, `TZ`, `LC_ALL`,
  `http_proxy`, `https_proxy`, `SSL_CERT_FILE`

```c
// BUG: trusting PATH from attacker, child inherits full env
char *editor = getenv("EDITOR");
execlp(editor, editor, filename, NULL);

// BUG: setuid binary inherits attacker's LD_PRELOAD
execve("/usr/sbin/helper", argv, environ);

// FIX: validate getenv, construct a minimal environment for children
const char *safe_env[] = {
    "PATH=/usr/bin:/bin",
    "HOME=/tmp",
    NULL
};
execve("/usr/sbin/helper", argv, safe_env);
```

```python
# BUG: trusting env in a web handler
db_host = os.environ["DB_HOST"]  # attacker set via CGI/container

# FIX: validate or use config file, scrub env for subprocesses
subprocess.run(cmd, env={"PATH": "/usr/bin", "HOME": "/tmp"})
```

The pattern: any code that reads `getenv()` / `os.environ` / `System.getenv()`
and uses the value in a security-sensitive operation (path construction,
dynamic loading, config selection, subprocess invocation) without validating
it. And any `exec`/`spawn` that inherits the full environment instead of
constructing a minimal one.

---

## 6. Unbounded Loop / Algorithmic Complexity

A loop whose iteration count depends on attacker-controlled input with
no upper bound. Causes CPU exhaustion or excessive allocation.

```c
// BUG: pkt->count from attacker
for (int i = 0; i < pkt->count; i++) {
    items[i] = parse_item(pkt);
}

// FIX: cap to maximum
if (pkt->count > MAX_ITEMS) return ERROR;
```

Also: quadratic or exponential regex (ReDoS), hash collision flooding,
deeply nested data structures causing O(n^2) serialization.

---

## 7. Resource Leak on Error Path

Acquiring a resource (memory, fd, lock, handle) and returning early on
a subsequent error without releasing it. Denial of service in long-running
processes.

```c
// BUG: buf leaked on validation failure
char *buf = malloc(size);
if (!buf) return ERROR;
if (validate(input) < 0) return ERROR;  // buf leaked

// FIX
if (validate(input) < 0) { free(buf); return ERROR; }
```

In any language: open files, database connections, locks, temp files,
network sockets. The pattern is: acquire → error path that skips release.

---

## 8. Error State Clobbered Before Check

Performing another operation between a failure and the error check.
The intervening call may reset the error indicator.

```c
// BUG: close() may reset errno
n = read(fd, buf, len);
close(fd);
if (n < 0) perror("read");  // errno from close, not read

// FIX: save error state immediately
n = read(fd, buf, len);
int saved_errno = errno;
close(fd);
errno = saved_errno;
```

In Python: catching a broad exception that swallows the real error.
In Go: `err` reassigned by a defer or subsequent call.

---

## 9. Null/Nil/None Dereference After Inverted Check

Checking for null and then using the pointer in the wrong branch.

```c
// BUG: uses p when it IS null
if (p == NULL) {
    p->cleanup();
}

// Also: checking the wrong variable
if (a != NULL) {
    b->method();  // b is the one that might be null
}
```

The shape: a null check exists but protects the wrong reference or
the wrong branch. More subtle than "no null check at all".

---

## 10. Recursive Processing Stack Overflow

Parsing or processing nested structures with recursion bounded only by
input depth. Crafted deep nesting exhausts the call stack.

```
// BUG: no depth limit
function parse_value(input):
    if input.is_object():
        parse_object(input)  // mutual recursion, no bound

// FIX: track and limit depth
function parse_value(input, depth):
    if depth > MAX_DEPTH: return error
    if input.is_object():
        parse_object(input, depth + 1)
```

Applies to: JSON, XML, ASN.1, protobuf, HTML, any recursive grammar.

---

## 11. Injection via String Interpolation

Constructing a query, template, or expression by interpolating user data.
The injected data is interpreted as code/structure, not as a value.

Specific forms:
- **SQL injection**: `"SELECT * FROM users WHERE id=" + user_id`
- **LDAP injection**: `"(uid=" + username + ")"`
- **XPath injection**: `"//user[@name='" + name + "']"`
- **Template injection**: rendering user input as a template expression
- **Header injection**: newlines in HTTP header values
- **Log injection**: newlines in log messages creating fake log entries

The fix is always: parameterized queries / prepared statements / escaping
functions specific to the target language.

---

## 12. Deserialization of Untrusted Data

Deserializing attacker-controlled data using a format that supports
arbitrary object instantiation or code execution.

Dangerous by default:
- Python: `pickle`, `yaml.load()` (without `SafeLoader`)
- Java: `ObjectInputStream`, various library deserializers (Jackson with
  default typing, XStream, etc.)
- PHP: `unserialize()`
- Ruby: `Marshal.load()`, `YAML.load()`
- .NET: `BinaryFormatter`, `XmlSerializer` with type info

---

## 13. Missing Authentication / Authorization Check

An endpoint, handler, or code path that performs a privileged operation
without verifying the caller's identity or permissions.

```
// BUG: no auth check before admin operation
function delete_user(request):
    user_id = request.params["id"]
    db.delete(user_id)

// FIX: verify caller is authorized
function delete_user(request):
    if not request.user.is_admin: return 403
    user_id = request.params["id"]
    db.delete(user_id)
```

Also: authorization bypass via parameter manipulation (changing `user_id`
in the request to access another user's data — IDOR).

---

## 14. Sensitive Data Exposure

Logging, returning in error messages, or storing in plaintext data that
should be protected: passwords, tokens, keys, PII.

```
// BUG: password in log
log.info("login attempt: user=%s pass=%s", user, password)

// BUG: stack trace with internals returned to client
except Exception as e:
    return {"error": str(e)}  // may include file paths, SQL, etc.
```

---

## 15. Cryptographic Weakness

Using broken or weak algorithms, hardcoded keys, predictable IVs, or
ECB mode. Common instances:

- MD5 or SHA1 for integrity/authentication (collision-vulnerable)
- ECB mode (pattern-preserving)
- Hardcoded symmetric keys or IVs
- `rand()` / `Math.random()` for security-sensitive values
- Comparing MACs with `==` instead of constant-time comparison
- Reusing nonces in AES-GCM or ChaCha20-Poly1305

---

## 16. Open Redirect

Redirecting to a URL taken from user input without validating the
destination. Used for phishing (victim sees trusted domain in the link).

```
// BUG: redirect_url from query parameter
return redirect(request.params["next"])

// FIX: validate destination is same-origin or allowlisted
url = request.params["next"]
if not is_safe_redirect(url): return 400
return redirect(url)
```

---

## 17. Server-Side Request Forgery (SSRF)

The application fetches a URL provided by the user. Attacker supplies
internal/cloud-metadata URLs to access internal services.

```
// BUG: url from user
response = http.get(request.params["url"])

// FIX: validate scheme, host, and block internal ranges
url = request.params["url"]
if not is_external_url(url): return 400
```

Watch for: `http://169.254.169.254` (cloud metadata), `file://`,
`gopher://`, DNS rebinding, redirect chains that land on internal hosts.

---

## 18. Race Condition in Check-Then-Act

A broader class than TOCTOU. Any sequence where a condition is verified
and then acted upon non-atomically, allowing concurrent modification.

```
// BUG: balance checked, then decremented — not atomic
if account.balance >= amount:
    account.balance -= amount  // concurrent request also passes the check

// FIX: atomic compare-and-swap, or serialized transaction
with db.transaction():
    if account.balance >= amount:
        account.balance -= amount
```

---

## 19. Incorrect Error Propagation

Swallowing errors, converting specific errors to generic ones, or
continuing execution after a partial failure.

```
// BUG: error from step 2 lost; step 3 runs on corrupt state
try:
    step1()
    step2()  // fails silently
    step3()  // runs with bad state from step2
except:
    pass
```

Also: `catch (Exception e)` that handles everything identically,
Go code that assigns `err` but never checks it, C code that ignores
negative return values.

---

## 20. Default/Example Credentials

Hardcoded passwords, API keys, or tokens in source code, config files,
or environment defaults.

```
// BUG
db_password = os.getenv("DB_PASS", "admin123")
api_key = "sk-proj-XXXXXXXX"
```

---

## 21. Insufficient Input Validation at Trust Boundary

Data crosses a trust boundary (network → server, user → kernel,
untrusted → trusted) without validation of type, range, length, or
format. This is the root cause enabling most other patterns.

```
// BUG: header_count from packet used directly as array index
process_headers(pkt->headers, pkt->header_count);

// FIX: validate at the boundary
if (pkt->header_count > MAX_HEADERS) return ERROR;
if (pkt->header_count * sizeof(Header) > pkt->remaining_bytes) return ERROR;
```
