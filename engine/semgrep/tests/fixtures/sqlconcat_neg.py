def parameterised(cur, uid):
    q = "SELECT * FROM users WHERE id = ?"
    cur.execute(q, (uid,))


def non_sql_concat(name):
    greeting = "hello " + name
    selected = "selected items: " + name
    return greeting + selected
