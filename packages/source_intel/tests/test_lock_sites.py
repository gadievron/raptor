"""Tests for the concurrency axis — lock_sites.cocci + LockSiteEvidence.

Two layers:
  * Unit: the message parser (`_parse_match_to_lock_site`) — deterministic,
    no spatch. Pins the COCCIRESULT shape, the kind/op enums, the
    `& foo` → `&foo` normalisation, and the structural-segment guard.
  * Real-spatch E2E: gated on spatch availability. Smoke fixture with
    every covered family fires; out-of-axis primitives (cpu_relax,
    atomic_inc, futex) do NOT fire.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from packages.source_intel.analyze import (
    LockSiteEvidence,
    SourceIntelResult,
    _parse_match_to_lock_site,
    analyze,
)


class _Match:
    """Shape-compatible stand-in for coccinelle.runner.SpatchMatch."""

    def __init__(self, message: str, file: str = "x.c", line: int = 1) -> None:
        self.message = message
        self.file = file
        self.line = line


# --- parser unit tests ----------------------------------------------------


def test_parser_accepts_canonical_message():
    out = _parse_match_to_lock_site(_Match(
        "lock_site:acquire:spin:spin_lock:&sl", file="d.c", line=12,
    ))
    assert out == [LockSiteEvidence(
        op="acquire", kind="spin", fn="spin_lock", lock_var="&sl",
        location=("d.c", 12), enclosing_function=None,
    )]


def test_parser_normalises_spatch_amp_spacing():
    # spatch renders `&sl` as `& sl`; consumers must see the normalised form
    # so grouping by lock_var doesn't fragment on whitespace artefacts.
    out = _parse_match_to_lock_site(_Match(
        "lock_site:acquire:mutex:mutex_lock:& m",
    ))
    assert out[0].lock_var == "&m"


def test_parser_rejects_unknown_op():
    assert _parse_match_to_lock_site(_Match(
        "lock_site:downgrade:spin:spin_lock:&sl",
    )) == []


def test_parser_rejects_unknown_kind():
    assert _parse_match_to_lock_site(_Match(
        "lock_site:acquire:rcu:rcu_read_lock:&p",
    )) == []


def test_parser_rejects_truncated_message():
    # Missing the lock_var segment — only 4 parts.
    assert _parse_match_to_lock_site(_Match(
        "lock_site:acquire:spin:spin_lock",
    )) == []


def test_parser_rejects_empty_fn():
    assert _parse_match_to_lock_site(_Match(
        "lock_site:acquire:spin::&sl",
    )) == []


def test_parser_ignores_other_rules():
    # A neighbouring rule's COCCIRESULT mustn't leak through the dispatch.
    assert _parse_match_to_lock_site(_Match("lsm:security_inode_permission")) == []
    assert _parse_match_to_lock_site(_Match("paired_free:kmalloc:kfree")) == []


def test_parser_preserves_colons_in_lock_var():
    # If a future C++ extension emits a scoped name (`Class::member`),
    # the colons in lock_var must survive the 4-way split.
    out = _parse_match_to_lock_site(_Match(
        "lock_site:acquire:pthread_mutex:pthread_mutex_lock:&Foo::Bar::m",
    ))
    assert out[0].lock_var == "&Foo::Bar::m"


def test_lock_sites_default_empty_on_bare_result():
    r = SourceIntelResult()
    assert r.lock_sites == ()


# --- real-spatch E2E (skipped in CI; runs locally) ------------------------


_LOCK_FIXTURE_HEADER = """\
typedef int spinlock_t;
typedef int rwlock_t;
typedef int pthread_mutex_t;
struct mutex { int x; };

void spin_lock(spinlock_t *l);
void spin_unlock(spinlock_t *l);
void spin_lock_irqsave(spinlock_t *l, unsigned long f);
void spin_unlock_irqrestore(spinlock_t *l, unsigned long f);
void mutex_lock(struct mutex *m);
int mutex_lock_interruptible(struct mutex *m);
void mutex_unlock(struct mutex *m);
void read_lock(rwlock_t *l);
void write_lock(rwlock_t *l);
void read_unlock(rwlock_t *l);
void write_unlock(rwlock_t *l);
int pthread_mutex_lock(pthread_mutex_t *m);
int pthread_mutex_unlock(pthread_mutex_t *m);

/* deliberately NOT covered by lock_sites.cocci */
void cpu_relax(void);
void atomic_inc(int *v);
int futex(int *uaddr, int futex_op);
"""

_LOCK_FIXTURE_BODY = """\
static spinlock_t sl;
static struct mutex m;
static rwlock_t rl;
static pthread_mutex_t pm;

int driver(void) {
    unsigned long flags;
    spin_lock(&sl);
    spin_unlock(&sl);
    spin_lock_irqsave(&sl, flags);
    spin_unlock_irqrestore(&sl, flags);
    mutex_lock(&m);
    mutex_unlock(&m);
    if (mutex_lock_interruptible(&m)) return -1;
    mutex_unlock(&m);
    read_lock(&rl); read_unlock(&rl);
    write_lock(&rl); write_unlock(&rl);
    pthread_mutex_lock(&pm);
    pthread_mutex_unlock(&pm);

    /* Out-of-axis primitives — must NOT appear in lock_sites. */
    cpu_relax();
    atomic_inc(&flags);
    futex((int *)&sl, 0);
    return 0;
}
"""


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("spatch"), reason="spatch not installed",
)
def test_e2e_lock_sites_covers_every_family(tmp_path: Path) -> None:
    (tmp_path / "lk.c").write_text(_LOCK_FIXTURE_HEADER + _LOCK_FIXTURE_BODY)
    r = analyze(tmp_path)

    # Every covered family fires at least once on the fixture.
    triples = {(s.kind, s.op, s.fn) for s in r.lock_sites}
    expected = {
        ("spin", "acquire", "spin_lock"),
        ("spin", "release", "spin_unlock"),
        ("spin", "acquire", "spin_lock_irqsave"),
        ("spin", "release", "spin_unlock_irqrestore"),
        ("mutex", "acquire", "mutex_lock"),
        ("mutex", "release", "mutex_unlock"),
        ("mutex", "acquire", "mutex_lock_interruptible"),
        ("rw", "acquire", "read_lock"),
        ("rw", "release", "read_unlock"),
        ("rw", "acquire", "write_lock"),
        ("rw", "release", "write_unlock"),
        ("pthread_mutex", "acquire", "pthread_mutex_lock"),
        ("pthread_mutex", "release", "pthread_mutex_unlock"),
    }
    missing = expected - triples
    assert not missing, f"families not captured: {sorted(missing)}"


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("spatch"), reason="spatch not installed",
)
def test_e2e_lock_sites_skips_out_of_axis_primitives(tmp_path: Path) -> None:
    # Atomics / CPU hints / futex aren't lock sites; they belong to other
    # axes (deferred). If they appear in lock_sites, our cocci is too broad.
    (tmp_path / "lk.c").write_text(_LOCK_FIXTURE_HEADER + _LOCK_FIXTURE_BODY)
    r = analyze(tmp_path)

    fns = {s.fn for s in r.lock_sites}
    assert "cpu_relax" not in fns
    assert "atomic_inc" not in fns
    assert "futex" not in fns


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("spatch"), reason="spatch not installed",
)
def test_e2e_lock_sites_carry_enclosing_function(tmp_path: Path) -> None:
    (tmp_path / "lk.c").write_text(_LOCK_FIXTURE_HEADER + _LOCK_FIXTURE_BODY)
    r = analyze(tmp_path)

    fns = {s.enclosing_function for s in r.lock_sites}
    # Every site comes from `driver` — no stray attributions.
    assert fns == {"driver"}, f"unexpected enclosing functions: {fns}"
