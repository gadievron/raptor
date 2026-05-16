# ruff: noqa: F821
# Fixture file: deliberately references undefined names
# (``compute_hash``, ``log_attempt``, ``constant_time_compare``)
# so the view() tests have realistic call-site shapes without
# pulling in real implementations.

def check_password(user, pw):
    """Check whether `pw` matches `user`'s hash."""
    if user is None:
        return -1
    hashed = compute_hash(pw)
    log_attempt(user)
    if constant_time_compare(user.pw_hash, hashed):
        return 0
    return 1


class Auth:
    def login(self, user, pw):
        return check_password(user, pw)

    def logout(self, user):
        pass
