"""Fixture tests for cancellation/free candidate matching.

Rows establish local syntactic candidates. Callback concurrency, registration,
container use and prior quiescence require separate review. The matcher retains
its existing heuristic suppressions; silence is not a lifetime-safety proof.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "teardown_lifetime.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_async_cancel_then_free_direct_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct dev_priv *priv)
            {
                timer_delete(&priv->poll_timer);
                kfree(priv);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "teardown_lifetime"

    def test_async_cancel_then_free_via_alias_fires(self, tmp_path):
        # The container is freed through the expression the local was
        # bound from (kfree(dev->private) after cancelling
        # &priv->timer) — the alias form.
        results = _run_rule(tmp_path, """\
            void bug(struct outer *dev)
            {
                struct dev_priv *priv = dev->private;

                if (priv) {
                    timer_delete(&priv->timer);
                    kfree(dev->private);
                }
            }
        """)
        assert len(results) == 1

    def test_async_work_cancel_then_free_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct conn *c)
            {
                cancel_delayed_work(&c->retry_work);
                kfree(c);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_sync_cancel_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct dev_priv *priv)
            {
                timer_delete_sync(&priv->poll_timer);
                kfree(priv);
            }
        """)
        assert results == []

    def test_sync_cancel_between_suppresses(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct dev_priv *priv)
            {
                del_timer(&priv->poll_timer);
                timer_delete_sync(&priv->poll_timer);
                kfree(priv);
            }
        """)
        assert results == []

    def test_free_of_unrelated_object_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct dev_priv *priv, struct scratch *tmp)
            {
                timer_delete(&priv->poll_timer);
                kfree(tmp);
            }
        """)
        assert results == []

    def test_self_handler_container_of_suppressed(self, tmp_path):
        # The function IS the work handler (container_of-derived
        # container): non-reentrancy of the executing item makes
        # plain cancel-then-free safe — must not fire.
        results = _run_rule(tmp_path, """\
            void handler(struct work_struct *work)
            {
                struct conn *c = container_of(work, struct conn, work);

                shutdown_call(c);
                cancel_work(&c->work);
                kfree(c);
            }
        """)
        assert results == []
