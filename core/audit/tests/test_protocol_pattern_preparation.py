"""Bounded protocol indexes and pattern facts retain direct-scan results."""

from dataclasses import asdict

import pytest

from core.audit import pattern_completeness as patterns
from core.audit import proto_length_checker as proto
from core.testing.module_bindings import patch_module_attribute


class _ObservedPattern:
    def __init__(self, pattern):
        self.pattern = pattern
        self.calls = 0

    def finditer(self, source):
        self.calls += 1
        return self.pattern.finditer(source)


def test_call_indexes_scan_once_and_keep_site_order():
    source = 'memcpy(a, x, n+n); memcpy(b, x, n); memcpy(a[2]+1, x, m); memcpy(a, x, n);'
    pattern = _ObservedPattern(proto._COPY_RE)
    sites = proto._ProtocolCalls(source, pattern, 2)
    expected = list(proto._COPY_RE.finditer(source))
    assert [m.start() for m in sites.matches(pattern, buffer='a')] == [expected[i].start() for i in (0, 2, 3)]
    assert [m.start() for m in sites.matches(pattern, length='n')] == [expected[i].start() for i in (0, 1, 3)]
    assert list(sites.matches(pattern, length='absent')) == []
    assert pattern.calls == 1


@pytest.mark.parametrize('kind', ['rows', 'characters', 'tokens'])
def test_index_overflow_falls_back_without_losing_any_calls(kind):
    if kind == 'rows':
        source = 'memcpy(a, x, n);\n' * 1025
    elif kind == 'characters':
        source = ('memcpy(a, x, ' + 'n' * 1000 + ');\n') * 270
    else:
        expression = '+'.join('v' + str(i) for i in range(160))
        source = ('memcpy(a, x, ' + expression + ');\n') * 60
    pattern = _ObservedPattern(proto._COPY_RE)
    sites = proto._ProtocolCalls(source, pattern, 2)
    expected = [m.start() for m in proto._COPY_RE.finditer(source)]
    assert [m.start() for m in sites.matches(pattern, buffer='a')] == expected
    assert [m.start() for m in sites.matches(pattern, buffer='a')] == expected
    assert sites.overflow and not sites.tokens and not sites.by_buffer and not sites.by_length
    assert pattern.calls == 3  # one bounded preparation plus two complete scans


def test_replaced_pattern_keeps_direct_scan_instead_of_stale_index():
    source = 'memcpy(a, x, n); memmove(b, x, m);'
    sites = proto._ProtocolCalls(source, proto._COPY_RE, 2)
    list(sites.matches(proto._COPY_RE, buffer='a'))
    replacement = _ObservedPattern(proto._COPY_RE)
    assert len(list(sites.matches(replacement, buffer='absent'))) == 2
    assert replacement.calls == 1


def test_replaced_token_provider_bypasses_prepared_tokens(monkeypatch):
    source = 'memcpy(a, x, n);'
    sites = proto._ProtocolCalls(source, proto._COPY_RE, 2)
    match = next(sites.matches(proto._COPY_RE, buffer='a'))
    calls = []

    def replaced(pattern, expression):
        calls.append(expression)
        return ['replacement']

    patch_module_attribute(monkeypatch, proto, 're', 'findall', replaced)
    assert sites.variables(match, 'n') == {'replacement'}
    assert len(list(sites.matches(proto._COPY_RE, buffer='absent'))) == 1
    assert calls == ['n']


def test_protocol_findings_keep_legacy_order_and_before_allocation_copy():
    source = ('n = ntohs(pkt);\n'
              'memcpy(a, pkt, n);\n'
              'a = malloc(n);\n'
              'recv(fd, a, n, 0);\n'
              'memmove(a, pkt, n);\n'
              'memcpy(stack, pkt, n);\n')
    findings = proto.check_proto_length('f', source, file='p.c')
    assert [(f.alloc_call, f.copy_call, f.line, f.confidence) for f in findings] == [
        ('malloc', 'memcpy', 1, 'high'), ('malloc', 'memmove', 1, 'high'),
        ('malloc', 'recv', 1, 'high'), ('', 'memcpy', 1, 'medium'),
    ]
    assert all(f.file == 'p.c' and f.length_var == 'n' for f in findings)


def test_repeated_line_facts_are_local_and_keep_fresh_findings(monkeypatch):
    source = 'n = ntohs(pkt);\n' + '// padding\n' * 450 + 'a = malloc(n);\n' + 'memcpy(a, pkt, n);\n' * 20
    actual = proto._find_line
    calls = []

    def observed(source, pos):
        calls.append(pos)
        return actual(source, pos)

    monkeypatch.setattr(proto, '_find_line', observed)
    monkeypatch.setattr(proto, '_LINE_IMPL', observed)
    first = proto.check_proto_length('f', source)
    second = proto.check_proto_length('f', source)
    assert len(first) == len(second) == 20 and first == second
    assert first[0] is not second[0]
    assert calls == [0, 0]


def test_line_helper_override_retains_per_finding_operations(monkeypatch):
    source = 'n = ntohs(pkt);\na = malloc(n);\nmemcpy(a, pkt, n);\nmemcpy(a, pkt, n);\n'
    lines = iter([17, 29])
    monkeypatch.setattr(proto, '_find_line', lambda *args: next(lines))
    assert [f.line for f in proto.check_proto_length('f', source)] == [17, 29]


def test_foreign_source_retains_direct_pattern_scans(monkeypatch):
    class Source(str):
        pass

    def unexpected(*args):
        raise AssertionError('foreign source used an index')

    source = Source('n = ntohs(pkt);\na = malloc(n);\nmemcpy(a, pkt, n);\n')
    monkeypatch.setattr(proto, '_ProtocolCalls', unexpected)
    assert len(proto.check_proto_length('f', source)) == 1


def test_glob_and_suffix_synonym_facts_remain_distinct():
    source = 'glob("*.yml")\nglob("*.yaml")\nx.endswith(".yml")\nx.endswith(".yml")\n'
    findings = patterns._detect_extension_synonym_gaps('p.py', source, source.splitlines())
    assert [(f.line, f.suggestion) for f in findings] == [
        (3, 'also check endswith(".yaml")'), (4, 'also check endswith(".yaml")'),
    ]


def test_synonym_cache_preserves_duplicate_order(monkeypatch):
    monkeypatch.setattr(patterns, '_EXTENSION_SYNONYMS', {'.yml': ('.yaml', '.yaml', '.htm')})
    source = 'glob("*.yml")\nglob("*.yml")'
    findings = patterns._detect_extension_synonym_gaps('p.py', source, source.splitlines())
    assert [f.suggestion for f in findings] == ['also match *.yaml', 'also match *.yaml', 'also match *.htm'] * 2
    assert [f.line for f in findings] == [1, 1, 1, 2, 2, 2]


def test_foreign_lowered_text_retains_every_membership_query():
    operations = []

    class Lowered(str):
        def __contains__(self, item):
            operations.append(item)
            return super().__contains__(item)

    class Source(str):
        def lower(self):
            return Lowered(super().lower())

    source = Source('glob("*.yml")\nglob("*.yml")')
    findings = patterns._detect_extension_synonym_gaps('p.py', source, source.splitlines())
    assert len(findings) == 2
    assert operations == ['*.yaml', '".yaml"', "'.yaml'"] * 2


def test_directory_lower_adapter_keeps_per_extension_calls():
    operations = []

    class Source(str):
        def lower(self):
            operations.append('lower')
            return super().lower()

    source = Source('.github/workflows/*.yml')
    findings = patterns._detect_directory_glob_gaps('p.py', source, source.splitlines())
    assert operations == ['lower', 'lower']
    assert len(findings) == 1 and findings[0].sibling_pattern == '*.yml'


def test_xref_join_retains_distinct_chain_provenance():
    primary = 'n = ntohs(pkt);'
    xref = ('// --- callee: first ---\na = malloc(n); memcpy(a, pkt, n);\n'
            '// --- callee: second ---\nb = malloc(n); recv(fd, b, n, 0);\n')
    findings = proto.check_proto_length('f', primary, xref_source=xref)
    assert [f.copy_call for f in findings] == ['memcpy', 'recv']
    assert all(f.line == 1 and f.confidence == 'medium' and '[cross-function]' in f.evidence for f in findings)
    assert len({str(asdict(f)) for f in findings}) == 2


def test_native_upper_bound_windows_match_copied_prefixes():
    source = 'xif (n < MAX) { work(); }\nif (n > LIMIT) { return; }\nwhile (i < n) { ++i; }\n'

    class Copied(str):
        pass

    for text in [source, '// padding\n' * 400 + source]:
        ends = list(range(-2, min(80, len(text)))) + list(range(len(text) - 80, len(text) + 3))
        for start in [0, 1, 2, -3, len(text)]:
            for end in ends:
                for name in ['n', 'i', 'MAX', 'absent']:
                    assert proto._var_has_upper_bound(text, name, end, start=start) == proto._var_has_upper_bound(Copied(text), name, end, start=start), (start, end, name)


def test_replaced_guard_pattern_keeps_copied_prefix_arguments(monkeypatch):
    received = []
    actual = proto._RETURN_CHECK_RE

    class ReturnChecks:
        def finditer(self, text):
            received.append(text)
            return actual.finditer(text)

    monkeypatch.setattr(proto, '_RETURN_CHECK_RE', ReturnChecks())
    source = '// padding\n' * 400 + 'if (n > MAX) { return; }\ntrailing'
    end = source.rindex('\n')
    assert proto._var_has_upper_bound(source, 'n', end) == 'MAX'
    assert received == [source[:end]]


def test_small_native_protocol_uses_direct_scans(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError('small function paid index setup')

    monkeypatch.setattr(proto, '_ProtocolCalls', unexpected)
    source = 'n = ntohs(pkt); a = malloc(n); memcpy(a, pkt, n);'
    assert len(proto.check_proto_length('f', source)) == 1


def test_enclosing_name_prefilter_keeps_unicode_and_foreign_lines():
    from core.audit import _util

    class Line(str):
        def __contains__(self, text):
            raise AssertionError('foreign line probed for a literal')

    lines = ['\u2003async def outer(x):', Line('    def inner(x):'), '    return 1']
    assert _util.find_enclosing_function(lines, 0) == 'outer'
    assert _util.find_enclosing_function(lines, 2) == 'inner'


def test_enclosing_prefilter_bounds_native_regex_work(monkeypatch):
    from core.audit import _util

    actual = _util.re
    calls = []

    def observed(pattern, line):
        calls.append(line)
        return actual.match(pattern, line)

    view = patch_module_attribute(monkeypatch, _util, 're', 'match', observed)
    monkeypatch.setattr(_util, '_ENCLOSING_RE_MODULE', view)
    monkeypatch.setattr(_util, '_ENCLOSING_MATCH_IMPL', observed)
    lines = ['def outer():'] + ['    work()'] * 200
    assert _util.find_enclosing_function(lines, 200) == 'outer'
    assert calls == ['def outer():']


def test_replaced_enclosing_regex_keeps_each_line_operation(monkeypatch):
    from core.audit import _util

    actual = _util.re
    calls = []

    def observed(pattern, line):
        calls.append(line)
        return actual.match(pattern, line)

    patch_module_attribute(monkeypatch, _util, 're', 'match', observed)
    lines = ['def outer():', '    work()', '    return 1']
    assert _util.find_enclosing_function(lines, 2) == 'outer'
    assert calls == list(reversed(lines))


def test_foreign_line_container_keeps_provider_lookup_before_subscription(monkeypatch):
    from core.audit import _util

    actual = _util.re
    calls = []

    def observed(pattern, line):
        calls.append(line)
        return actual.match(pattern, line)

    class Lines(list):
        def __getitem__(self, index):
            patch_module_attribute(monkeypatch, _util, 're', 'match', observed)
            return super().__getitem__(index)

    assert _util.find_enclosing_function(Lines(['def f():', 'work()']), 1) == 'f'
    # The original default matcher was already loaded before the first getitem.
    assert calls == ['def f():']
