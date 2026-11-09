"""Normal study queue retains independently bound learning requests."""

from dataclasses import replace

from core.audit.knowledge_requests import KnowledgeOrigin, register_requests
from core.audit.orchestrator import StudyQueue


def test_bound_requests_are_not_suppressed_by_an_earlier_subject(tmp_path):
    queue = StudyQueue()
    origin = KnowledgeOrigin("first", "owned.c", "f", 1, 1, None)
    first = register_requests({"reading_list": [{"subject": "foo_t"}]}, origin).accepted[0]
    later = register_requests({"reading_list": [{"subject": "foo_t", "context": "ownership"}]},
                              replace(origin, pass_id="second")).accepted[0]
    queue.mark_studied({"foo_t"})
    assert queue.enqueue_knowledge(first)
    assert queue.enqueue_knowledge(later)
    assert queue.dequeue_batch(timeout=0) == [first, later]
    queue.set_working(False)
    queue.signal_consumer_done()
    assert not queue.enqueue_knowledge(first)
    assert not queue.pending_concepts()


def test_bound_request_after_producer_close_is_explicitly_refused():
    queue = StudyQueue()
    origin = KnowledgeOrigin("first", "owned.c", "f", 1, 1, None)
    request = register_requests({"reading_list": [{"subject": "foo_t"}]}, origin).accepted[0]
    queue.signal_producer_done()
    assert not queue.enqueue_knowledge(request)
    assert queue.is_done()
