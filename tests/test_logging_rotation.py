import logging
import os

from gramps_webapi.app import RecreatingRotatingFileHandler, create_app
from gramps_webapi.const import TREE_MULTI


def test_logs_recreated_after_deletion(tmp_path):
    config = {
        "TREE": TREE_MULTI,
        "SECRET_KEY": "secret",
        "USER_DB_URI": "sqlite://",
        "LOGIN_LOG_PATH": str(tmp_path / "login.log"),
        "AUTH_LOG_PATH": str(tmp_path / "auth.log"),
    }
    create_app(config=config, config_from_env=False)

    login_logger = logging.getLogger("login")
    auth_logger = logging.getLogger("auth")

    login_logger.info("first")
    auth_logger.info("first")

    login_path = tmp_path / "login.log"
    auth_path = tmp_path / "auth.log"
    assert login_path.exists()
    assert auth_path.exists()

    os.remove(login_path)
    os.remove(auth_path)

    login_logger.info("second")
    auth_logger.info("second")

    assert login_path.exists()
    assert auth_path.exists()


def test_rotation_limits_size(tmp_path):
    log_path = tmp_path / "rotate.log"
    handler = RecreatingRotatingFileHandler(
        log_path, maxBytes=100, backupCount=1, encoding="utf-8", delay=True
    )
    logger = logging.getLogger("rotate_test")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()
    logger.addHandler(handler)

    for _ in range(20):
        logger.info("x" * 20)

    handler.close()
    assert log_path.stat().st_size <= 100
    assert (tmp_path / "rotate.log.1").exists()

