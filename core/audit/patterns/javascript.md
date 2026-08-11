# JavaScript / TypeScript Vulnerability Patterns

JS/TS-specific patterns. Language-agnostic patterns (injection, TOCTOU,
etc.) are in `common.md` and always apply alongside these.

---

## 1. Prototype Pollution

Merging user-controlled objects into internal objects. Attacker sets
`__proto__`, `constructor`, or `prototype` to inject properties into
all objects.

```js
// BUG: deep merge with user input
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
merge(config, JSON.parse(userInput));
// userInput: {"__proto__": {"isAdmin": true}}
// now ({}).isAdmin === true for ALL objects

// FIX: block dangerous keys
const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
if (BLOCKED.has(key)) continue;
```

Also: `Object.assign()`, lodash `_.merge()` (pre-4.17.12), spread
operator is safe (only own enumerable properties).

---

## 2. Cross-Site Scripting (XSS)

Inserting user data into HTML without encoding. The browser executes
attacker-controlled script.

```js
// BUG: stored XSS — unescaped user content in HTML
element.innerHTML = userComment;

// BUG: reflected XSS — query param in response
res.send(`<p>Search: ${req.query.q}</p>`);

// FIX: use textContent or encode
element.textContent = userComment;
// or template engine with auto-escaping
res.render('search', { query: req.query.q });
```

Also: `document.write()`, `eval()`, `setTimeout(string)`,
`href="javascript:..."`, React `dangerouslySetInnerHTML`.

---

## 3. Server-Side eval / Function Constructor

Executing user-controlled strings as code on the server.

```js
// BUG
const result = eval(userExpression);
const fn = new Function('return ' + userInput);

// FIX: use a safe expression parser
const result = safeEval(userExpression);  // e.g. mathjs, expr-eval
```

Also: `vm.runInNewContext()` is NOT a sandbox — it can escape.

---

## 4. NoSQL Injection

MongoDB query operators in user input bypass authentication or
extract data.

```js
// BUG: req.body.password = {"$gt": ""}
const user = await User.findOne({
    username: req.body.username,
    password: req.body.password  // operator injection
});

// FIX: ensure value is a string
if (typeof req.body.password !== 'string') return res.status(400).end();
```

Also: `$regex`, `$where` (executes JS), `$ne` to bypass equality checks.

---

## 5. Insecure JWT Handling

JWTs accepted without proper verification, or using the `none`
algorithm, or trusting the `alg` header from the token.

```js
// BUG: alg=none accepted
const payload = jwt.verify(token, secret);  // some libs accept alg=none

// BUG: secret used for both HMAC and RSA — attacker sends HMAC-signed
//      token with the RSA public key as the HMAC secret
jwt.verify(token, publicKey);

// FIX: specify allowed algorithms
const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
```

---

## 6. Regular Expression Denial of Service (ReDoS)

Regex with nested quantifiers on overlapping character classes.
Crafted input causes exponential backtracking.

```js
// BUG: catastrophic backtracking
const re = /^(a+)+$/;
re.test('aaaaaaaaaaaaaaaaaaaaa!');  // hangs

// FIX: restructure regex
const re = /^a+$/;
```

Also: user-supplied regex compiled with `new RegExp(userInput)`.

---

## 7. Race Condition in async/await

Concurrent async operations sharing mutable state without serialization.
Node.js is single-threaded but async interleavings cause logical races.

```js
// BUG: two concurrent requests read, modify, write
async function transfer(from, to, amount) {
    const fromBal = await getBalance(from);
    if (fromBal < amount) throw new Error('insufficient');
    await setBalance(from, fromBal - amount);  // stale read
    await setBalance(to, (await getBalance(to)) + amount);
}

// FIX: use atomic operation or transaction
await db.transaction(async (tx) => {
    // serialized inside transaction
});
```

---

## 8. Unvalidated Redirect

Redirecting to a user-controlled URL. Used for phishing.

```js
// BUG
res.redirect(req.query.next);

// FIX: validate destination
const url = new URL(req.query.next, 'https://mysite.com');
if (url.origin !== 'https://mysite.com') return res.status(400).end();
res.redirect(url.pathname);
```

---

## 9. Command Injection via child_process

`exec()` passes through shell. User data enables injection.

```js
// BUG: shell injection
const { exec } = require('child_process');
exec(`convert ${filename} output.png`);

// FIX: execFile with argv array
const { execFile } = require('child_process');
execFile('convert', [filename, 'output.png']);
```

---

## 10. Path Traversal via path.join

`path.join()` does not prevent `../` traversal. `path.resolve()` with
an absolute user path replaces the base entirely.

```js
// BUG: userPath = "../../etc/passwd"
const filePath = path.join(uploadDir, userPath);

// FIX
const resolved = path.resolve(uploadDir, userPath);
if (!resolved.startsWith(path.resolve(uploadDir) + path.sep)) {
    throw new Error('traversal');
}
```

---

## 11. SSRF via fetch/axios/http

Fetching user-controlled URLs. Attacker reaches internal services.

```js
// BUG
const resp = await fetch(req.body.url);

// FIX: validate URL, block internal ranges
const parsed = new URL(req.body.url);
if (isPrivateHost(parsed.hostname)) throw new Error('SSRF blocked');
```

Watch for: redirect following (default on), DNS rebinding.

---

## 12. Insecure Deserialization (node-serialize)

Libraries like `node-serialize` execute functions during deserialization.

```js
// BUG: user-controlled serialized data with IIFE
const serialize = require('node-serialize');
const obj = serialize.unserialize(userInput);
// userInput can contain: {"rce":"_$$ND_FUNC$$_function(){...}()"}

// FIX: use JSON.parse
const obj = JSON.parse(userInput);
```

---

## 13. Missing CSRF Protection

State-changing endpoints that accept requests without verifying origin.
Attacker's page submits forms/requests to the victim's session.

```js
// BUG: POST handler with no CSRF token check
app.post('/transfer', (req, res) => {
    transfer(req.session.user, req.body.to, req.body.amount);
});

// FIX: verify CSRF token
app.post('/transfer', csrfProtection, (req, res) => { ... });
```

Also: `SameSite=None` cookies without CSRF tokens, CORS misconfiguration
with `Access-Control-Allow-Origin: *` + credentials.

---

## 14. Timing Attack on String Comparison

Using `===` to compare secrets (tokens, passwords, API keys). Short-circuit
evaluation leaks the correct prefix via timing.

```js
// BUG: early exit reveals prefix length
if (token === expectedToken) { ... }

// FIX: constant-time comparison
const crypto = require('crypto');
if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) { ... }
```

---

## 15. Type Coercion

JS loose equality and implicit type conversion produce unexpected results
in security checks.

```js
// BUG: "0" == false is true; [] == false is true
if (userInput == false) { /* "safe" path */ }

// BUG: parseInt stops at first non-digit
if (parseInt(age) > 18) { ... }
// parseInt("18 ; DROP TABLE users") === 18

// FIX: strict equality and full validation
if (userInput === false) { ... }
const age = Number(ageStr);
if (!Number.isInteger(age) || age <= 18) { ... }
```

---

## 16. Uninitialized Buffer (Node.js)

`Buffer.allocUnsafe()` and `Buffer.allocUnsafeSlow()` return memory
with stale heap contents. Sending it without fully writing leaks data.

```js
// BUG: if n < size, bytes [n..size) contain heap garbage
const buf = Buffer.allocUnsafe(size);
const n = stream.read(buf);
socket.write(buf);  // sends uninitialized bytes

// FIX: use Buffer.alloc (zero-filled) or slice to actual length
const buf = Buffer.alloc(size);
// or: socket.write(buf.subarray(0, n));
```
