def assemble(name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return query


def any_variable_name(owner):
    stmt = "delete from sessions where owner = " + owner
    return stmt


def percent_format(uid):
    q = "UPDATE users SET active = 1 WHERE id = %s" % uid
    return q
