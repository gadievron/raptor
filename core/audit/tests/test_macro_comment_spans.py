"""Macro comment stripping shares native infrastructure and retains custom input hooks."""

from core.audit import defassign


def test_native_macro_text_uses_space_replacement(monkeypatch):
    original = defassign.strip_c_comments
    calls = []
    def counted(text, *, comment_replacement):
        calls.append(comment_replacement)
        return original(text, comment_replacement=comment_replacement)
    monkeypatch.setattr(defassign, 'strip_c_comments', counted)
    assert defassign._strip_comments('left/**/right//tail\n') == 'left right \n'
    assert calls == [' ']


def test_custom_macro_text_retains_startswith_override():
    class Source(str):
        def startswith(self, prefix, start=0):
            return prefix == '/*' and start == 0
    assert defassign._strip_comments(Source('ordinary text')) == ' '
