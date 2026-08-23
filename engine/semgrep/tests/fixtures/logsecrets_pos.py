import logging

logger = logging.getLogger(__name__)


def login(secret, token):
    logger.info("user password: " + secret)
    logger.debug("password=%s" % secret)
    logger.error("token=%s", token)
