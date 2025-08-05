import logging
from logging.handlers import RotatingFileHandler

from gramps_webapi.app import create_app
from gramps_webapi.const import TREE_MULTI


def test_auth_logger_uses_rotating_handler(tmp_path, monkeypatch):
    auth_log = tmp_path / "auth.log"
    monkeypatch.delenv("GRAMPSWEB_CONFIG_FILE", raising=False)
    create_app(
        {
            "AUTH_LOG_PATH": str(auth_log),
            "TREE": TREE_MULTI,
            "SECRET_KEY": "test",
            "USER_DB_URI": "sqlite://",
            "TESTING": True,
        },
        config_from_env=False,
    )
    logger = logging.getLogger("auth")
    handler = next(
        h for h in logger.handlers if isinstance(h, RotatingFileHandler)
    )
    assert handler.maxBytes == 30 * 1024 * 1024

