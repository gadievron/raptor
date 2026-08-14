# Python Vulnerability Patterns

Python-specific patterns. Language-agnostic patterns (injection, path
traversal, TOCTOU, etc.) are in `common.md` and always apply alongside
these.

---

## 1. Unsafe Deserialization

`pickle`, `marshal`, `shelve`, and `yaml.load()` (without SafeLoader)
execute arbitrary code during deserialization.

```python
# BUG
data = pickle.loads(request.body)
config = yaml.load(user_input)

# FIX
data = json.loads(request.body)  # or a schema-validated format
config = yaml.safe_load(user_input)
```

Also: `dill`, `cloudpickle`, `jsonpickle` — all unsafe by design.

---

## 2. Command Injection via shell=True

`subprocess` with `shell=True` passes the command through the shell.
User data in the command string enables injection.

```python
# BUG
subprocess.run(f"convert {filename} output.png", shell=True)

# FIX: argv list, no shell
subprocess.run(["convert", filename, "output.png"])
```

Also: `os.system()`, `os.popen()`, backtick-equivalent in older code.

---

## 3. SQL Injection via String Formatting

Building SQL queries by interpolating user input instead of using
parameterized queries.

```python
# BUG
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)

# FIX: parameterized
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

Also applies to ORM `.raw()` / `.extra()` methods.

---

## 4. Path Traversal via os.path.join

`os.path.join` does NOT prevent traversal. If a component is absolute,
it discards everything before it.

```python
# BUG: user_path = "/etc/passwd" → result is "/etc/passwd"
path = os.path.join(base_dir, user_path)

# Also BUG: user_path = "../../etc/passwd"
path = os.path.join(upload_dir, user_path)

# FIX: resolve and check containment
path = os.path.realpath(os.path.join(base_dir, user_path))
if not path.startswith(os.path.realpath(base_dir) + os.sep):
    raise ValueError("path traversal")
```

---

## 5. Server-Side Template Injection (SSTI)

Rendering user input as a template. Template engines (Jinja2, Mako,
Django) can execute arbitrary code.

```python
# BUG: user_input rendered as template
template = jinja2.Template(user_input)
result = template.render()

# FIX: user input is DATA, not template
template = jinja2.Template("Hello {{ name }}")
result = template.render(name=user_input)
```

Jinja2 sandbox can be escaped; treat user-controlled templates as
code execution.

---

## 6. Regex Denial of Service (ReDoS)

Regex with nested quantifiers on overlapping character classes.
Crafted input causes exponential backtracking.

```python
# BUG: catastrophic backtracking on "aaa...!" input
pattern = re.compile(r"(a+)+$")

# FIX: use atomic groups (Python 3.11+) or restructure
pattern = re.compile(r"a+$")
```

Also: user-controlled regex patterns compiled without timeout or
complexity limits.

---

## 7. Insecure Temporary File

Using `tempfile.mktemp()` (creates name but not file) or predictable
filenames in `/tmp`. Race condition between creation and use.

```python
# BUG: race between name generation and file creation
path = tempfile.mktemp()
with open(path, 'w') as f:
    f.write(data)

# FIX: atomic creation
with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(data)
    path = f.name
```

---

## 8. XML External Entity (XXE)

Default XML parsers resolve external entities, enabling file read,
SSRF, and denial of service.

```python
# BUG: default parser resolves external entities
tree = etree.parse(user_xml)

# FIX: disable external entities
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(user_xml, parser)

# For defusedxml
import defusedxml.ElementTree as ET
tree = ET.parse(user_xml)
```

---

## 9. Mutable Default Argument

Default mutable arguments (list, dict, set) are shared across all
calls. Mutations persist between invocations.

```python
# BUG: items is shared across calls
def add_item(name, items=[]):
    items.append(name)
    return items

# FIX
def add_item(name, items=None):
    if items is None:
        items = []
    items.append(name)
    return items
```

Security relevance: one user's data leaks into another user's response.

---

## 10. Unsafe eval / exec

Executing user-controlled strings as Python code.

```python
# BUG
result = eval(user_expression)
exec(user_code)

# FIX: use ast.literal_eval for data, or a sandboxed evaluator
result = ast.literal_eval(user_expression)  # only literals
```

Also: `compile()` + `exec()`, `importlib.import_module()` with user
input, `__import__()`.

---

## 11. Incorrect Exception Handling

Catching too broadly, swallowing exceptions, or catching and continuing
with corrupt state.

```python
# BUG: hides real errors (KeyboardInterrupt, SystemExit, bugs)
try:
    process(data)
except:
    pass

# FIX: catch specific exceptions
try:
    process(data)
except ValueError as e:
    logger.warning("invalid data: %s", e)
    return default
```

---

## 12. Information Leak via Exception

Returning stack traces, internal paths, or query details to the client.

```python
# BUG
@app.errorhandler(500)
def error(e):
    return str(e), 500  # may include SQL, file paths, secrets

# FIX
@app.errorhandler(500)
def error(e):
    logger.exception("internal error")
    return "Internal error", 500
```

---

## 13. Weak Cryptographic Primitives

Using `hashlib.md5()`, `hashlib.sha1()` for integrity, `random` for
tokens, or ECB mode.

```python
# BUG: md5 for integrity check
digest = hashlib.md5(data).hexdigest()

# BUG: random for token (predictable)
token = ''.join(random.choices(string.ascii_letters, k=32))

# FIX
digest = hashlib.sha256(data).hexdigest()
token = secrets.token_urlsafe(32)
```

---

## 14. SSRF via requests/urllib

Fetching a URL from user input. Attacker accesses internal services
or cloud metadata.

```python
# BUG
response = requests.get(user_url)

# FIX: validate scheme and host
parsed = urllib.parse.urlparse(user_url)
if parsed.hostname in BLOCKED_HOSTS or is_private_ip(parsed.hostname):
    raise ValueError("blocked")
```

Watch for: redirects to internal hosts, DNS rebinding, `file://` scheme.

---

## 15. Race Condition in File Operations

Non-atomic file operations where concurrent access can corrupt state.

```python
# BUG: read-modify-write race
data = json.load(open(path))
data["count"] += 1
json.dump(data, open(path, "w"))

# FIX: use file locking or atomic write
import fcntl
with open(path, "r+") as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    data = json.load(f)
    data["count"] += 1
    f.seek(0); f.truncate()
    json.dump(data, f)
```

---

## 16. Mass Assignment via **kwargs / dict merge

Merging user-controlled dicts into internal state, overwriting keys
the user shouldn't control.

```python
# BUG: user can set is_admin=True
user = User(**request.json)

# FIX: explicit allowlist
allowed = {"name", "email"}
user = User(**{k: v for k, v in request.json.items() if k in allowed})
```

Django equivalent: mass assignment via `Model.objects.create(**data)`.

---

## 17. Zip Slip

Extracting archives without validating that member paths stay within
the target directory.

```python
# BUG: member.name may contain "../"
with zipfile.ZipFile(upload) as z:
    z.extractall(target_dir)

# FIX: validate each member
for info in z.infolist():
    target = os.path.realpath(os.path.join(target_dir, info.filename))
    if not target.startswith(os.path.realpath(target_dir) + os.sep):
        raise ValueError("zip slip")
    z.extract(info, target_dir)
```

Also applies to tarfile (use `tarfile.data_filter` in Python 3.12+).

---

## 18. Mutable Object as Dict Key / Set Member

Objects used as dict keys or in sets that are later mutated. The hash
changes but the object stays in the wrong bucket — lookups return wrong
results or silently miss.

```python
# BUG: mutating a list used indirectly via object identity
class Session:
    def __init__(self, roles):
        self.roles = roles
    def __hash__(self):
        return hash(tuple(self.roles))
    def __eq__(self, other):
        return self.roles == other.roles

sessions = {session: user}
session.roles.append("admin")  # hash changed
sessions[session]  # KeyError — permission lookup fails silently
```

Security relevance: permission lookups fail after mutation, either
granting unintended access or silently dropping restrictions.
