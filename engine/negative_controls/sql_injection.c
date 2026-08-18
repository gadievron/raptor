/* Negative control: "sql injection" keyword family.
 *
 * Parameterized query — user input reaches the statement only through
 * a bound parameter.  The SQL text contains SELECT and '%' (a literal
 * LIKE wildcard), so presence-style regexes still match.
 */
#include <sqlite3.h>

int find_user(sqlite3 *db, const char *needle, sqlite3_stmt **out)
{
    static const char *q =
        "SELECT id FROM users WHERE name LIKE '%' || ? || '%'";
    int rc = sqlite3_prepare_v2(db, q, -1, out, 0);
    if (rc != SQLITE_OK) {
        return rc;
    }
    return sqlite3_bind_text(*out, 1, needle, -1, SQLITE_TRANSIENT);
}
