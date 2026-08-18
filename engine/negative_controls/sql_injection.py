"""Negative control: "sql injection" keyword family (Python).

Parameterized query — user input is bound, never interpolated. The SQL
text contains SELECT and a literal LIKE '%' wildcard, so presence-style
regexes still match.
"""


def find_user(cursor, needle):
    cursor.execute(
        "SELECT id FROM users WHERE name LIKE '%' || ? || '%'",
        (needle,),
    )
    return cursor.fetchall()
