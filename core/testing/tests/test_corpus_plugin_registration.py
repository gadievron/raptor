"""Corpus ownership fixtures remain local to their intended consumers."""

from core.build import artifacts
from core.inventory.binary_oracle_corpora import _cache
from core.project import project, registry_home

BORROWED_LOGGERS = (artifacts.logger, _cache.logger)


def test_corpus_fixtures_are_not_global_plugin(request):
    assert not request.config.pluginmanager.hasplugin(
        "core.inventory.tests.test_corpus_cache_lifecycle"
    )


def test_unrelated_consumer_keeps_borrowed_loggers():
    assert artifacts.logger is BORROWED_LOGGERS[0]
    assert _cache.logger is BORROWED_LOGGERS[1]


def test_unrelated_consumer_keeps_coherent_registry_root():
    assert registry_home.projects_dir() == project.PROJECTS_DIR
