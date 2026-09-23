def leading_space(name):
    query = "  SELECT * FROM users WHERE name = '" + name + "'"
    return query


def percent_leading_ws(uid):
    q = " UPDATE users SET active = 1 WHERE id = %s" % uid
    return q
