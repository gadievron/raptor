"""Protection status stays in the session banner and requires kernel checks."""
import pytest

from core.startup import init, install_guard


def test_ordinary_startup_has_no_protection_notice(monkeypatch):
    monkeypatch.delenv('RAPTOR_INSTALL_PROTECTED', raising=False)
    def unexpected():
        pytest.fail('ordinary startup must not probe installation protection')
    monkeypatch.setattr(install_guard, 'verify_inside', unexpected)
    assert init.installation_protection_notice() is None


def test_environment_marker_alone_cannot_claim_protection(monkeypatch):
    monkeypatch.setenv('RAPTOR_INSTALL_PROTECTED', '1')
    def refused():
        raise install_guard.ProtectionError('not protected')
    monkeypatch.setattr(install_guard, 'verify_inside', refused)
    notice = init.installation_protection_notice()
    assert 'could not be verified' in notice
    assert 'protection is active' not in notice


@pytest.mark.parametrize('tool_checks_fail', [False, True])
@pytest.mark.parametrize('verified', [False, True])
def test_notice_is_inside_printed_and_saved_banner(tmp_path, monkeypatch, capsys, tool_checks_fail, verified):
    monkeypatch.setenv('RAPTOR_INSTALL_PROTECTED', '1')
    def verify():
        if not verified:
            raise install_guard.ProtectionError('not protected')
    monkeypatch.setattr(install_guard, 'verify_inside', verify)
    monkeypatch.setattr(init, 'REPO_ROOT', tmp_path)
    monkeypatch.setattr(init, 'read_logo', lambda *args: 'RAPTOR')
    monkeypatch.setattr(init, 'read_random_quote', lambda: 'quote')
    def failed():
        raise OSError('tool probe failed')
    monkeypatch.setattr(init, 'check_tools', failed if tool_checks_fail else lambda: ([], [], []))
    monkeypatch.setattr(init, 'check_tool_updates', lambda: set())
    monkeypatch.setattr(init, 'check_llm', lambda: ([], []))
    monkeypatch.setattr(init, 'check_env', lambda unavailable: ([], []))
    monkeypatch.setattr(init, 'check_lang', lambda: (None, []))
    monkeypatch.setattr(init, 'check_active_project', lambda: 'Project: fixture')
    init.main()
    output = capsys.readouterr().out
    expected = ('Installation protection is active.' if verified
                else 'installation protection could not be verified')
    saved = (tmp_path / 'out/.startup-output').read_text()
    assert saved == output.rstrip('\n')
    for text in (output, saved):
        assert text.index(expected) < text.index('raptor:~$ quote')
        if not tool_checks_fail:
            assert text.index('Project: fixture') < text.index(expected)
            assert text.index(expected) < text.index('For defensive security')
        notice_lines = [line for line in text.split('\n') if line.startswith('  ')
                        and ('protection' in line or '--protect-install' in line)]
        assert all(len(line) <= 77 for line in notice_lines)
        assert expected in text
        assert text.rstrip().endswith('raptor:~$ quote')
        if verified:
            assert 'without --protect-install' in ' '.join(text.split())
        else:
            assert 'protection is active' not in text
