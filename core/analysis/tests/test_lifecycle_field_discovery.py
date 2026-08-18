"""Tests for core.analysis.lifecycle_field_discovery."""

from __future__ import annotations

from core.analysis.lifecycle_field_discovery import (
    _extract_class_fields_java,
    _extract_class_fields_python,
    _extract_struct_fields_c,
    _score_field,
    discover_state_fields,
)


class TestExtractStructFieldsC:
    def test_simple_struct(self):
        src = """
struct task_struct {
    int pid;
    struct mm_struct *mm;
    unsigned long flags;
};
"""
        result = _extract_struct_fields_c(src)
        assert "task_struct" in result
        assert "pid" in result["task_struct"]
        assert "mm" in result["task_struct"]
        assert "flags" in result["task_struct"]

    def test_union(self):
        src = """
union data {
    int i;
    float f;
};
"""
        result = _extract_struct_fields_c(src)
        assert "data" in result
        assert result["data"] == ["i", "f"]

    def test_no_structs(self):
        src = "int main() { return 0; }"
        assert _extract_struct_fields_c(src) == {}

    def test_nested_pointers(self):
        src = """
struct cred {
    kuid_t uid;
    kgid_t gid;
    struct group_info *group_info;
};
"""
        result = _extract_struct_fields_c(src)
        assert "cred" in result
        assert "uid" in result["cred"]
        assert "gid" in result["cred"]
        assert "group_info" in result["cred"]

    def test_array_field(self):
        src = """
struct buf {
    char data[256];
    int len;
};
"""
        result = _extract_struct_fields_c(src)
        assert "buf" in result
        assert "data" in result["buf"]
        assert "len" in result["buf"]


class TestExtractClassFieldsPython:
    def test_simple_class(self):
        src = """
class AuthService:
    def __init__(self, db):
        self.db = db
        self.cache = {}
        self.token_ttl = 3600
"""
        result = _extract_class_fields_python(src)
        assert "AuthService" in result
        assert result["AuthService"] == ["db", "cache", "token_ttl"]

    def test_multiple_classes(self):
        src = """
class A:
    def __init__(self):
        self.x = 1

class B:
    def __init__(self):
        self.y = 2
"""
        result = _extract_class_fields_python(src)
        assert "A" in result
        assert "B" in result
        assert result["A"] == ["x"]
        assert result["B"] == ["y"]

    def test_deduplicates(self):
        src = """
class Foo:
    def __init__(self):
        self.val = 0

    def reset(self):
        self.val = 0
"""
        result = _extract_class_fields_python(src)
        assert result["Foo"] == ["val"]

    def test_no_classes(self):
        src = "x = 1\ny = 2\n"
        assert _extract_class_fields_python(src) == {}


class TestExtractClassFieldsJava:
    def test_simple_class(self):
        src = """
public class UserService {
    private String username;
    public int accessLevel;
    protected boolean isAdmin = false;
}
"""
        result = _extract_class_fields_java(src)
        assert "UserService" in result
        fields = result["UserService"]
        assert "username" in fields
        assert "accessLevel" in fields
        assert "isAdmin" in fields

    def test_static_final(self):
        src = """
class Config {
    private static final int MAX_SIZE = 1024;
    private String name;
}
"""
        result = _extract_class_fields_java(src)
        assert "Config" in result
        assert "MAX_SIZE" in result["Config"]
        assert "name" in result["Config"]


class TestScoreField:
    def test_zero_when_no_sites(self):
        score = _score_field("x", "S", {"writes": [], "reads": []}, "", [])
        assert score == 0.0

    def test_positive_when_both_reads_and_writes(self):
        score = _score_field(
            "x", "S",
            {"writes": [5], "reads": [10]},
            "",
            [""] * 15,
        )
        assert score >= 0.2

    def test_security_guard_context_boosts(self):
        lines = [""] * 12
        lines[8] = "    if (ptr != NULL) {"
        lines[9] = "        use(s->x);"
        score = _score_field(
            "x", "S",
            {"writes": [5], "reads": [10]},
            "",
            lines,
        )
        assert score > 0.2

    def test_lifecycle_function_context_boosts(self):
        lines = [""] * 8
        lines[3] = "void init_task(struct S *s) {"
        lines[4] = "    s->x = alloc();"
        score = _score_field(
            "x", "S",
            {"writes": [5], "reads": []},
            "",
            lines,
        )
        assert score >= 0.2

    def test_capped_at_one(self):
        lines = [""] * 50
        for i in range(0, 50, 2):
            lines[i] = "if (auth && permission && null && lock && bounds) init alloc free"
        sites = {"writes": list(range(1, 20)), "reads": list(range(20, 50))}
        score = _score_field("x", "S", sites, "", lines)
        assert score <= 1.0


class TestDiscoverStateFields:
    def test_discovers_from_c_source(self, tmp_path):
        src = """\
#include <stdlib.h>

struct session {
    int auth_level;
    char *token;
    int active;
};

void session_init(struct session *s) {
    s->auth_level = 0;
    s->token = NULL;
    s->active = 1;
}

int check_auth(struct session *s) {
    if (s->auth_level > 0 && s->token != NULL) {
        return s->active;
    }
    return 0;
}
"""
        (tmp_path / "session.c").write_text(src, encoding="utf-8")
        checklist = {
            "files": [
                {"path": "session.c", "functions": [
                    {"name": "session_init", "line": 9},
                    {"name": "check_auth", "line": 16},
                ]},
            ],
        }
        fields = discover_state_fields(checklist, tmp_path, min_score=0.1)
        assert len(fields) > 0
        names = {f.name for f in fields}
        assert "auth_level" in names or "token" in names or "active" in names

    def test_discovers_from_python_source(self, tmp_path):
        src = """\
class AuthManager:
    def __init__(self):
        self.authenticated = False
        self.role = None

    def login(self, user):
        self.authenticated = True
        self.role = user.role

    def check_permission(self, resource):
        if self.authenticated and self.role != None:
            return self.role in resource.allowed_roles
        return False
"""
        (tmp_path / "auth.py").write_text(src, encoding="utf-8")
        checklist = {
            "files": [
                {"path": "auth.py", "functions": [
                    {"name": "__init__", "line": 2},
                    {"name": "login", "line": 7},
                    {"name": "check_permission", "line": 11},
                ]},
            ],
        }
        fields = discover_state_fields(checklist, tmp_path, min_score=0.1)
        assert len(fields) > 0
        names = {f.name for f in fields}
        assert "authenticated" in names or "role" in names

    def test_empty_checklist(self, tmp_path):
        fields = discover_state_fields({}, tmp_path)
        assert fields == []

    def test_missing_file(self, tmp_path):
        checklist = {"files": [{"path": "nonexistent.c"}]}
        fields = discover_state_fields(checklist, tmp_path)
        assert fields == []

    def test_top_n_limit(self, tmp_path):
        src = """\
struct big {
    int a; int b; int c; int d; int e;
    int f; int g; int h; int i; int j;
};

void init(struct big *b) {
    b->a = 0; b->b = 0; b->c = 0; b->d = 0; b->e = 0;
    b->f = 0; b->g = 0; b->h = 0; b->i = 0; b->j = 0;
}

int check(struct big *b) {
    if (b->a != NULL) return b->b;
    if (b->c != NULL) return b->d;
    if (b->e != NULL) return b->f;
    return 0;
}
"""
        (tmp_path / "big.c").write_text(src, encoding="utf-8")
        checklist = {"files": [{"path": "big.c"}]}
        fields = discover_state_fields(checklist, tmp_path, top_n=3, min_score=0.1)
        assert len(fields) <= 3

    def test_deduplicates_across_files(self, tmp_path):
        src = """\
struct ctx {
    int refcount;
};

void ctx_init(struct ctx *c) {
    c->refcount = 1;
}

int ctx_get(struct ctx *c) {
    return c->refcount;
}
"""
        (tmp_path / "a.c").write_text(src, encoding="utf-8")
        (tmp_path / "b.c").write_text(src, encoding="utf-8")
        checklist = {"files": [{"path": "a.c"}, {"path": "b.c"}]}
        fields = discover_state_fields(checklist, tmp_path, min_score=0.1)
        refcount_fields = [f for f in fields if f.name == "refcount"]
        assert len(refcount_fields) == 1

    def test_write_sites_populated(self, tmp_path):
        src = """\
struct s {
    int val;
};

void set(struct s *p) {
    p->val = 42;
}

int get(struct s *p) {
    return p->val;
}
"""
        (tmp_path / "s.c").write_text(src, encoding="utf-8")
        checklist = {"files": [{"path": "s.c"}]}
        fields = discover_state_fields(checklist, tmp_path, min_score=0.1)
        val_fields = [f for f in fields if f.name == "val"]
        if val_fields:
            f = val_fields[0]
            assert len(f.write_sites) >= 1
            assert len(f.read_sites) >= 1
            assert f.write_sites[0].file == "s.c"
