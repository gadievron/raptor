"""Operation-bound overflow disproofs and retired demotion provenance."""

import logging

logger = logging.getLogger(__name__)

RETIRED_BOUNDS_DEMOTION_PREFIX = '[smt-infeasible:'
SOURCE_OVERFLOW_DISPROOF_PREFIX = '[smt-disproof:'


def source_overflow_demotion_reason(
    hypothesis: str, source: str, *, file_path: str, function_name: str,
    integer_abi=None,
) -> str | None:
    """Demote only on the scoped source operation's typed overflow obligation.

    A contradictory guard elsewhere in a function cannot establish that
    the claimed operation is safe. The disproof binder must establish the
    operation, entry domains, reaching predicates, and explicit target ABI.
    """
    if not hypothesis or not source:
        return None
    try:
        from .condition_smt import disprove_integer_overflow

        result = disprove_integer_overflow(
            hypothesis, source, file_path=file_path,
            function_name=function_name, integer_abi=integer_abi,
        )
        if result.disproved is True:
            return SOURCE_OVERFLOW_DISPROOF_PREFIX + ' integer overflow impossible (Z3 UNSAT)]'
    except Exception:
        logger.debug('source overflow disproof failed for %s:%s',
                     file_path, function_name, exc_info=True)
    return None
