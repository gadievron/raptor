"""Tests for the comparator-intake family-size ceiling.

The census's group floors are mins; MAX_FAMILY_MEMBERS is the max
that never existed — the backstop against producers that do not cap
(every in-tree formation layer caps at or under it, so honest inputs
are unaffected). Selection above the ceiling is seeded-random, never
a sortable prefix; the uniform-absence scanner instead REFUSES
oversized families (its claim quantifies over the whole family, so a
sample would lie).
"""

from __future__ import annotations

import textwrap

from core.audit.consistency_dimensions import (
    MAX_FAMILY_MEMBERS,
    _intake_capped,
    detect_interface_deviations,
)
from core.audit.sibling_analysis import SiblingGroup, SiblingPath
from core.testing import requires_ts


class TestIntakeCap:
    def test_under_ceiling_passes_through_in_order(self):
        members = list(range(MAX_FAMILY_MEMBERS))
        kept, capped = _intake_capped(members)
        assert kept == members
        assert capped is False

    def test_over_ceiling_samples_a_subset(self):
        members = list(range(MAX_FAMILY_MEMBERS * 3))
        kept, capped = _intake_capped(members)
        assert capped is True
        assert len(kept) == MAX_FAMILY_MEMBERS
        assert set(kept) <= set(members)

    def test_selection_is_not_a_deterministic_prefix(self):
        # Seeded-random survivors: across builds the kept set varies,
        # so an attacker cannot name the deviant past a fixed cut.
        # (One draw equalling the prefix has probability ~1e-9 for
        # 32-of-96; twenty draws all equalling it is a broken RNG.)
        members = list(range(MAX_FAMILY_MEMBERS * 3))
        prefix = members[:MAX_FAMILY_MEMBERS]
        draws = [_intake_capped(members)[0] for _ in range(20)]
        assert any(d != prefix for d in draws)


_GUARDED = textwrap.dedent("""\
    def {name}(p):
        if p is None:
            return None
        return emit(p)
""")


class TestComparatorIntake:
    @requires_ts("python")
    def test_interface_vote_never_exceeds_the_ceiling(self):
        # One unguarded deviant in an oversized family: whenever the
        # sampled vote sees it, the emitted deviation's family size
        # must be the CAPPED size (reverting the ceiling emits n=52
        # here and fails; when the sample misses the deviant the
        # loop is empty, which the capped path also satisfies).
        n = MAX_FAMILY_MEMBERS + 20
        names = [f"handler_{i:03d}" for i in range(n)]
        sources = {"app.py": "\n".join(
            (
                f"def {name}(p):\n    return emit(p)\n"
                if name == names[0]
                else _GUARDED.format(name=name)
            )
            for name in names
        )}
        group = SiblingGroup(
            group_id="dispatch:app:big",
            sibling_type="dispatch_site",  # type: ignore[arg-type]
            description="oversized family",
            siblings=[
                SiblingPath(label=name, file="app.py", function=name)
                for name in names
            ],
        )
        devs = detect_interface_deviations(sources, [group])
        for dev in devs:
            assert dev.n <= MAX_FAMILY_MEMBERS

    @requires_ts("python")
    def test_sampling_is_marked_on_every_receipt_surface(self):
        # In-band degradation: a reviewer must never read "31/32
        # conform" as the whole family — the deviation description,
        # the serialized record, and the PeerEvidence provenance all
        # carry the sampled-of-N marker. The sample is drawn per
        # call, so retry until a draw includes the deviant (miss
        # probability per draw ~0.38; 50 misses ~ 1e-21).
        n = MAX_FAMILY_MEMBERS + 20
        names = [f"handler_{i:03d}" for i in range(n)]
        sources = {"app.py": "\n".join(
            (
                f"def {name}(p):\n    return emit(p)\n"
                if name == names[0]
                else _GUARDED.format(name=name)
            )
            for name in names
        )}
        group = SiblingGroup(
            group_id="dispatch:app:big",
            sibling_type="dispatch_site",  # type: ignore[arg-type]
            description="oversized family",
            siblings=[
                SiblingPath(label=name, file="app.py", function=name)
                for name in names
            ],
        )
        for _ in range(50):
            devs = detect_interface_deviations(sources, [group])
            if devs:
                break
        assert devs, "no draw sampled the deviant in 50 attempts"
        dev = devs[0]
        assert dev.sampled_from == n
        assert (
            f"seeded sample of {dev.n} of the family's {n} members"
            in dev.description
        )
        assert dev.to_dict()["sampled_from"] == n
        assert dev.peer_evidence is not None
        assert f"sampled{dev.n}of{n}" in dev.peer_evidence.provenance

    @requires_ts("python")
    def test_negative_space_marks_sampled_votes(self):
        from core.audit.negative_space import (
            check_sibling_negative_space,
        )

        n = MAX_FAMILY_MEMBERS + 20
        names = [f"render_{i:03d}" for i in range(n)]
        gaps = [
            {
                "name": name, "file": "app.py", "line": i + 1,
                "source": (
                    "def f(x):\n    return x\n" if i == 0 else
                    "def f(x):\n    return html_escape(x)\n"
                ),
            }
            for i, name in enumerate(names)
        ]

        class _Conv:
            concern = "escaping"
            pattern = r"html_escape"
            locations = frozenset()
            confidence = 1.0

        group = SiblingGroup(
            group_id="dispatch:app:render",
            sibling_type="dispatch_site",  # type: ignore[arg-type]
            description="oversized family",
            siblings=[
                SiblingPath(label=name, file="app.py",
                            function=name)
                for name in names
            ],
        )
        for _ in range(50):
            findings = check_sibling_negative_space(
                gaps, [_Conv()], peer_groups=[group],
            )
            if findings:
                break
        assert findings, "no draw sampled the deviant in 50 attempts"
        assert any(
            "seeded sample of" in f.expected for f in findings
        )

    @requires_ts("python")
    def test_uniform_absence_refuses_oversized_families(self):
        from core.audit.uniform_absence import uniform_absence_records

        n = MAX_FAMILY_MEMBERS + 4
        names = [f"handler_{i:03d}" for i in range(n)]
        sources = {"app.py": "\n".join(
            f"def {name}(p):\n    return emit(p)\n"
            for name in names
        )}
        group = SiblingGroup(
            group_id="interface_slot:x",
            sibling_type="interface_slot",  # type: ignore[arg-type]
            description="oversized family",
            siblings=[
                SiblingPath(label=name, file="app.py", function=name)
                for name in names
            ],
        )
        assert uniform_absence_records(sources, [group]) == []
