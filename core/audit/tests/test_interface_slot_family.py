"""Interface-implementor parity over interface-slot families (L7).

The slot census makes ops-struct slot implementations (and subclass
override sets) voting families for the standing parity comparator —
detection-grade, prepass-lead-only, no new verdict path. These tests
pin the end-to-end chain census → layer → comparator on C sources:
peers guard, the deviant doesn't, the lead surfaces under the single
consistency namespace.
"""

from __future__ import annotations

from core.analysis.interface_slots import interface_slot_families
from core.analysis.peer_groups import (
    GROUP_TYPE_INTERFACE_SLOT,
    _interface_slot_groups,
)
from core.audit.consistency_dimensions import (
    detect_interface_deviations,
)
from core.audit.peer_evidence import is_detection_rule_id
from core.testing import requires_ts

_GUARDED = """\
int {name}(struct pkt *p) {{
    if (!p)
        return -1;
    return emit(p->data, p->len);
}}
"""

_UNGUARDED = """\
int {name}(struct pkt *p) {{
    return emit(p->data, p->len);
}}
"""

_OPS = """\
static const struct pkt_ops tcp_ops = {{ .send = tcp_send }};
static const struct pkt_ops udp_ops = {{ .send = udp_send }};
static const struct pkt_ops raw_ops = {{ .send = raw_send }};
static const struct pkt_ops icmp_ops = {{ .send = icmp_send }};
"""


def _sources(deviant: str | None) -> dict[str, str]:
    bodies = []
    for name in ("tcp_send", "udp_send", "raw_send", "icmp_send"):
        tpl = _UNGUARDED if name == deviant else _GUARDED
        bodies.append(tpl.format(name=name))
    return {"src/net.c": "\n".join(bodies) + "\n" + _OPS.format()}


def _groups(sources: dict[str, str]):
    fams = interface_slot_families(sources)
    assert fams is not None
    functions = [
        {"name": n, "file": "src/net.c", "line": 1}
        for n in ("tcp_send", "udp_send", "raw_send", "icmp_send")
    ]
    return _interface_slot_groups(fams, functions)


@requires_ts("c")
def test_deviant_slot_member_surfaces_as_detection_lead():
    sources = _sources(deviant="raw_send")
    groups = _groups(sources)
    assert any(
        g.sibling_type == GROUP_TYPE_INTERFACE_SLOT for g in groups
    )
    devs = detect_interface_deviations(sources, groups)
    null_devs = [
        d for d in devs if d.property_name == "null_guard"
    ]
    assert len(null_devs) == 1
    dev = null_devs[0]
    assert dev.enclosing_function == "raw_send"
    assert dev.n == 4
    assert dev.conforming == 3
    assert dev.peer_evidence is not None
    # Detection-grade under the single consistency namespace — the
    # census can never classify code as vulnerable on its own.
    assert is_detection_rule_id(dev.peer_evidence.rule_id)
    assert dev.peer_evidence.rule_id.startswith("consistency:")


@requires_ts("c")
def test_uniform_family_produces_no_deviation():
    sources = _sources(deviant=None)
    devs = detect_interface_deviations(sources, _groups(sources))
    assert [d for d in devs if d.property_name == "null_guard"] == []
