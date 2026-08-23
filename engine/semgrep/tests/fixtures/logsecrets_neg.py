import logging

logger = logging.getLogger(__name__)


def housekeeping(count):
    logger.info("password rotation complete")
    logger.debug("count: %d", count)
    logger.error("login failed for request")
