"""Tests for the check-then-create compound race detector."""

from __future__ import annotations

import textwrap

from core.audit.check_then_create import scan_function, scan_gaps

_RACY = textwrap.dedent("""\
    func (s *store) Ensure(ctx context.Context, key string) (*L, error) {
        v, err := s.Get(ctx, key)
        if err != nil {
            return nil, err
        } else if v != nil {
            return v, nil
        }

        l, err := build(ctx, key)
        if err != nil {
            return nil, err
        }

        s.mu.Lock()
        s.refs[key] = l
        s.mu.Unlock()

        return l, nil
    }
""")


class TestPositive:
    def test_unspanned_compound_fires(self):
        findings = scan_function("a.go", "Ensure", _RACY)
        assert len(findings) == 1
        f = findings[0]
        assert f.key == "key"
        assert f.map_name == "s.refs"
        assert f.check_line == 2
        assert f.lock_line < f.write_line
        assert "check-then-create" in f.description()


class TestNegatives:
    def test_double_checked_registration_suppressed(self):
        src = textwrap.dedent("""\
            func (s *store) Ensure(ctx context.Context, key string) (*L, error) {
                v, err := s.Get(ctx, key)
                if err != nil {
                    return nil, err
                } else if v != nil {
                    return v, nil
                }

                l := build(key)

                s.mu.Lock()
                if cur, ok := s.refs[key]; ok {
                    s.mu.Unlock()
                    return cur, nil
                }
                s.refs[key] = l
                s.mu.Unlock()

                return l, nil
            }
        """)
        assert scan_function("a.go", "Ensure", src) == []

    def test_lock_spanning_compound_suppressed(self):
        src = textwrap.dedent("""\
            func (s *store) Ensure(ctx context.Context, key string) (*L, error) {
                s.mu.Lock()
                defer s.mu.Unlock()
                if v, ok := s.refs[key]; ok {
                    return v, nil
                }
                l := build(key)
                s.refs[key] = l
                return l, nil
            }
        """)
        # The check is a map read under the spanning lock — the write
        # region has a re-check (the same keyed read) and the lock is
        # held across; either suppression path must keep this silent.
        assert scan_function("a.go", "Ensure", src) == []

    def test_no_early_check_no_finding(self):
        src = textwrap.dedent("""\
            func (s *store) Put(key string, l *L) {
                s.mu.Lock()
                s.refs[key] = l
                s.mu.Unlock()
            }
        """)
        assert scan_function("a.go", "Put", src) == []

    def test_unlocked_write_out_of_scope(self):
        src = textwrap.dedent("""\
            func (s *store) Ensure(key string) *L {
                if v, ok := s.refs[key]; ok {
                    return v
                }
                l := build(key)
                s.refs[key] = l
                return l
            }
        """)
        assert scan_function("a.go", "Ensure", src) == []


class TestScanGaps:
    def test_lines_are_file_absolute_and_non_go_skipped(self):
        text = "// header\n// header\n" + _RACY
        gaps = [
            {"file": "a.go", "name": "Ensure",
             "line_start": 3, "line_end": 3 + _RACY.count("\n")},
            {"file": "b.c", "name": "cfn", "line_start": 1, "line_end": 5},
        ]
        findings = scan_gaps(gaps, {"a.go": text, "b.c": "int x;"})
        assert len(findings) == 1
        f = findings[0]
        assert f.check_line == 4          # 2 + offset 2
        assert f.function == "Ensure"
