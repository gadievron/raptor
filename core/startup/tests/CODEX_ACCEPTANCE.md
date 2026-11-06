# Codex scan isolation acceptance

This is a developer acceptance procedure for the Codex integration. It
supplements `test_codex_native_acceptance.py`: the app-server preflight tests
do not prove model-driven lifecycle hooks or scanner isolation work.

Launch the integration against a small, disposable fixture and request this
command in the normal Codex tool sandbox, using the fixture's absolute path:

```bash
python3 raptor.py scan --repo /tmp/raptor-codex-smoke --sandbox strict
```

`strict` explicitly requests RAPTOR's shared fail-closed scan policy. It is
not a Codex-specific override of the default `full` profile. Early strict
preflight requires the shared scan-preflight change to be present on the branch.

If nested namespaces are unavailable, expect isolation-failure exit code **3**
before scanner work starts. That validates refusal behavior, not successful
scan acceptance. Compare namespace availability in the launching terminal and
the normal Codex tool sandbox; a read-only installation or outer sandbox does
not establish the scanner's own isolation.

Do not automatically retry with elevated permissions or a weaker profile.
Successful scan acceptance requires the fixture scan to complete under the
requested isolation, with no hook failures. Record hook timeouts separately;
a successful lightweight diagnostic command does not resolve earlier timeouts.
