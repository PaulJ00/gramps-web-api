#
# Gramps Web API - A RESTful API for the Gramps genealogy program
#
# Copyright (C) 2020      David Straub
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

"""API resource endpoints."""

from functools import wraps
from typing import Iterable

import logging
from flask import abort, request
from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request
from flask_jwt_extended.exceptions import NoAuthorizationError

from ..auth.const import CLAIM_LIMITED_SCOPE


AUTH_LOGGER = logging.getLogger("auth")


def _log_authentication() -> None:
    """Log a successful authentication."""
    try:
        identity = get_jwt_identity()
    except Exception:  # pragma: no cover - fallback if identity missing
        identity = "unknown"
    AUTH_LOGGER.info(
        "Authentication success: user %s from %s", identity, request.remote_addr
    )


def jwt_required(func):
    """Check JWT.

    Raise if claims include limited_scope key.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        _log_authentication()
        claims = get_jwt()
        if claims.get(CLAIM_LIMITED_SCOPE):
            raise NoAuthorizationError
        return func(*args, **kwargs)

    return wrapper


def fresh_jwt_required(func):
    """Check JWT and require it to be fresh.

    Raise if claims include limited_scope key.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request(fresh=True)
        _log_authentication()
        claims = get_jwt()
        if claims.get(CLAIM_LIMITED_SCOPE):
            raise NoAuthorizationError
        return func(*args, **kwargs)

    return wrapper


def jwt_limited_scope_required(func):
    """Check JWT.

    Raise if claims do not include limited_scope key.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        _log_authentication()
        claims = get_jwt()
        if not claims.get(CLAIM_LIMITED_SCOPE):
            raise NoAuthorizationError
        return func(*args, **kwargs)

    return wrapper


def jwt_refresh_token_required(func):
    """Check JWT."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request(refresh=True)
        _log_authentication()
        return func(*args, **kwargs)

    return wrapper


def has_permissions(scope: Iterable[str]) -> bool:
    """Check a set of permissions and return False if any are missing."""
    claims = get_jwt()
    user_permissions = set(claims.get("permissions", []))
    required_permissions = set(scope)
    missing_permissions = required_permissions - user_permissions
    if missing_permissions:
        return False
    return True


def require_permissions(scope: Iterable[str]) -> None:
    """Require a set of permissions or fail with a 403."""
    if not has_permissions(scope):
        abort(403)
