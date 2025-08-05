import logging
from logging.handlers import RotatingFileHandler

from gramps_webapi.app import create_app


def test_auth_logger_uses_rotating_handler(tmp_path):
    auth_log = tmp_path / "auth.log"
    app = create_app({"AUTH_LOG_PATH": str(auth_log)})
    logger = logging.getLogger("auth")
    handler = next(
        h for h in logger.handlers if isinstance(h, RotatingFileHandler)
    )
    assert handler.maxBytes == 30 * 1024 * 1024

