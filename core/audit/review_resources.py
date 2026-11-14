"""Run-local retirement prototype; no dispatch, source or budget authority."""
from collections.abc import Callable


class RunReviewResources:
    def __init__(self) -> None:
        self._callbacks: list[Callable[[], None]] = []
        self._retired = False
        self._retiring = False
        self._after: Callable[[], None] | None = None
        self._after_retired = False

    def register(self, callback: Callable[[], None]) -> None:
        if self._retired:
            raise RuntimeError("review resources already retired")
        self._callbacks.append(callback)

    def retire(
        self, *, primary_error: BaseException | None = None,
        after: Callable[[], None] | None = None,
    ) -> None:
        # The final run cleanup may arrive after the normal review boundary
        # already retired these resources. It still runs once, after them.
        if after is not None and self._after is None and not self._after_retired:
            self._after = after
        if self._retiring:
            return
        callbacks = []
        if not self._retired:
            self._retired = True
            callbacks, self._callbacks = self._callbacks, []
        self._retiring = True
        errors: list[BaseException] = []
        try:
            for callback in reversed(callbacks):
                try:
                    callback()
                except BaseException as error:
                    errors.append(error)
            # A resource callback can request final cleanup reentrantly. Defer
            # that callback until every resource above has been attempted.
            if self._after is not None and not self._after_retired:
                callback, self._after = self._after, None
                self._after_retired = True
                try:
                    callback()
                except BaseException as error:
                    errors.append(error)
        finally:
            self._retiring = False
        self.raise_cleanup_errors(errors, primary_error=primary_error)

    @staticmethod
    def raise_cleanup_errors(
        errors: list[BaseException], *, primary_error: BaseException | None = None,
    ) -> None:
        if primary_error is not None:
            for error in errors:
                BaseException.add_note(primary_error,
                    "Review resource retirement also failed: " + type(error).__name__)
            return
        if errors:
            # With no operation error, cancellation is never hidden by an
            # earlier ordinary cleanup failure. Otherwise retain the first.
            selected = next((error for error in errors
                             if not isinstance(error, Exception)), errors[0])
            for error in errors:
                if error is not selected:
                    BaseException.add_note(selected,
                        "Another review resource retirement failed: " + type(error).__name__)
            raise selected
