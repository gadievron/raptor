"""Tests for core.audit.condition_classifier — guard condition categorization."""

from __future__ import annotations

from core.audit.condition_classifier import classify_condition, classify_conditions_batch


class TestAuthClassification:
    """Detect authentication/authorization guard patterns."""

    def test_is_authenticated(self):
        assert classify_condition("user.is_authenticated") == "auth"

    def test_is_authorized(self):
        assert classify_condition("is_authorized(user)") == "auth"

    def test_check_permission(self):
        assert classify_condition("check_permission(user, 'admin')") == "auth"

    def test_has_role(self):
        assert classify_condition("has_role(ctx, 'editor')") == "auth"

    def test_require_auth(self):
        assert classify_condition("require_auth()") == "auth"

    def test_verify_token(self):
        assert classify_condition("verify_token(jwt_str)") == "auth"

    def test_is_admin(self):
        assert classify_condition("user.is_admin") == "auth"

    def test_login_required_decorator(self):
        assert classify_condition("@login_required") == "auth"

    def test_permission_required_decorator(self):
        assert classify_condition("@permission_required('edit')") == "auth"

    def test_jwt_required_decorator(self):
        assert classify_condition("@jwt_required") == "auth"

    def test_go_middleware(self):
        assert classify_condition("AuthMiddleware(handler)") == "auth"

    def test_session_valid(self):
        assert classify_condition("session.is_valid") == "auth"

    def test_token_authenticated(self):
        assert classify_condition("token.authenticated") == "auth"


class TestBoundsClassification:
    """Detect size/length/index bounds check patterns."""

    def test_len_less_than(self):
        assert classify_condition("len(data) < MAX_SIZE") == "bounds"

    def test_length_property(self):
        assert classify_condition("buf.length < limit") == "bounds"

    def test_size_check(self):
        assert classify_condition("size <= capacity") == "bounds"

    def test_index_bounds(self):
        assert classify_condition("idx < array_len") == "bounds"

    def test_offset_check(self):
        assert classify_condition("offset >= 0") == "bounds"

    def test_sizeof_comparison(self):
        assert classify_condition("n < sizeof(buffer)") == "bounds"

    def test_max_limit(self):
        assert classify_condition("max_size > input_len") == "bounds"

    def test_buffer_size(self):
        assert classify_condition("buf_len > 0") == "bounds"

    def test_count_property(self):
        assert classify_condition("items.count < 100") == "bounds"

    def test_range_check(self):
        assert classify_condition("0 <= x < 256") == "bounds"


class TestNullClassification:
    """Detect null/nil/None/nullptr check patterns."""

    def test_python_is_none(self):
        assert classify_condition("x is None") == "null"

    def test_python_is_not_none(self):
        assert classify_condition("data is not None") == "null"

    def test_c_null_check(self):
        assert classify_condition("ptr != NULL") == "null"

    def test_go_nil_check(self):
        assert classify_condition("err != nil") == "null"

    def test_cpp_nullptr(self):
        assert classify_condition("node != nullptr") == "null"

    def test_js_null(self):
        assert classify_condition("value !== null") == "null"

    def test_ruby_nil(self):
        assert classify_condition("obj.nil?") == "null"


class TestConfigClassification:
    """Detect configuration/debug/feature flag patterns."""

    def test_debug_flag(self):
        assert classify_condition("debug") == "config"

    def test_feature_flag(self):
        assert classify_condition("feature_enabled") == "config"

    def test_env_check(self):
        assert classify_condition("os.environ['DEBUG']") == "config"

    def test_settings_access(self):
        assert classify_condition("settings['allow_raw']") == "config"

    def test_config_dot_access(self):
        assert classify_condition("config.strict_mode") == "config"

    def test_production_check(self):
        assert classify_condition("production") == "config"

    def test_dry_run(self):
        assert classify_condition("dry_run") == "config"

    def test_skip_auth_flag(self):
        # Note: this matches config first (skip_auth) not auth
        assert classify_condition("skip_auth") == "config"

    def test_process_env(self):
        assert classify_condition("process.env.NODE_ENV") == "config"


class TestErrorClassification:
    """Detect error status check patterns."""

    def test_errno_check(self):
        assert classify_condition("errno == EACCES") == "error"

    def test_status_comparison(self):
        assert classify_condition("status == 0") == "error"

    def test_retval_check(self):
        assert classify_condition("ret < 0") == "error"

    def test_named_error_constant(self):
        assert classify_condition("result == ERROR_ACCESS_DENIED") == "error"

    def test_is_error(self):
        assert classify_condition("is_error(result)") == "error"

    def test_http_status(self):
        assert classify_condition("status_code != 200") == "error"

    def test_except_keyword(self):
        assert classify_condition("except ValueError:") == "error"


class TestTypeClassification:
    """Detect type check patterns."""

    def test_isinstance(self):
        assert classify_condition("isinstance(x, str)") == "type"

    def test_typeof(self):
        assert classify_condition("typeof value === 'string'") == "type"

    def test_instanceof(self):
        assert classify_condition("obj instanceof Buffer") == "type"

    def test_python_type_check(self):
        assert classify_condition("type(x) == int") == "type"


class TestResourceClassification:
    """Detect resource availability check patterns."""

    def test_file_exists(self):
        assert classify_condition("path.exists()") == "resource"

    def test_is_file(self):
        assert classify_condition("os.path.is_file(path)") == "resource"

    def test_is_connected(self):
        assert classify_condition("db.is_connected") == "resource"

    def test_is_open(self):
        assert classify_condition("file.is_open") == "resource"

    def test_can_read(self):
        assert classify_condition("can_read(fd)") == "resource"


class TestUnknownClassification:
    """Conditions that don't match any category."""

    def test_plain_variable(self):
        assert classify_condition("x") == "unknown"

    def test_arithmetic(self):
        assert classify_condition("a + b") == "unknown"

    def test_string_comparison(self):
        assert classify_condition("name == 'admin'") == "unknown"

    def test_empty_string(self):
        assert classify_condition("") == "unknown"


class TestPriorityOrder:
    """When a condition matches multiple categories, the highest-priority wins."""

    def test_auth_beats_error(self):
        # "err != nil" matches error, but "is_authenticated" is auth
        # If both present, first match wins
        assert classify_condition("is_authenticated and err != nil") == "auth"

    def test_bounds_beats_null(self):
        # "len(data)" is bounds, even if "!= None" also appears
        assert classify_condition("len(data) > 0") == "bounds"


class TestBatch:
    def test_batch_classification(self):
        conditions = [
            "user.is_admin",
            "len(buf) < 100",
            "ptr != NULL",
            "foobar",
        ]
        results = classify_conditions_batch(conditions)
        assert results == ["auth", "bounds", "null", "unknown"]

    def test_batch_empty(self):
        assert classify_conditions_batch([]) == []
