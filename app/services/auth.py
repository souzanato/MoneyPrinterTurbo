"""
Authentication service for MoneyPrinterTurbo WebUI.

Provides password hashing (PBKDF2 + SHA-256), credential verification,
default user initialization, and a Streamlit authentication gate.
"""

import hashlib
import secrets
import time as _time

import streamlit as st
from loguru import logger

from app.config import config

# Short-lived single-use tokens issued after login. They survive the hard
# browser reload that avoids the Streamlit "Bad delta path" error during the
# login→app widget-tree transition.
# Format: {token: (username, expires_at)}
_pending_auth_tokens: dict[str, tuple[str, float]] = {}


def _issue_auth_token(username: str) -> str:
    """Issue a 60-second single-use token to authenticate the post-reload session."""
    token = secrets.token_urlsafe(32)
    now = _time.time()
    expired = [k for k, (_, exp) in _pending_auth_tokens.items() if exp < now]
    for k in expired:
        del _pending_auth_tokens[k]
    _pending_auth_tokens[token] = (username, now + 60)
    return token


def _consume_auth_token(token: str) -> str | None:
    """Validate and consume a pending auth token. Returns username or None."""
    entry = _pending_auth_tokens.pop(token, None)
    if entry and _time.time() < entry[1]:
        return entry[0]
    return None


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hash a password using PBKDF2 with SHA-256.

    Returns (hash_hex, salt_hex).
    """
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()
    return hashed, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify a password against a stored PBKDF2 hash (constant-time compare)."""
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


def _get_users() -> dict:
    """Return the users dictionary from config, or an empty dict."""
    return config._cfg.get("users", {}) or {}


def _save_users(users: dict) -> None:
    """Persist the users dictionary to config.toml."""
    config._cfg["users"] = users
    config.save_config()


def check_credentials(username: str, password: str) -> bool:
    """Return True if the username/password combination is valid."""
    users = _get_users()
    if username not in users:
        return False
    user_data = users[username]
    stored_hash = user_data.get("password_hash", "")
    stored_salt = user_data.get("salt", "")
    if not stored_hash or not stored_salt:
        return False
    return verify_password(password, stored_hash, stored_salt)


def init_default_users() -> None:
    """Create the default admin user if no users exist yet.

    Default user:
      - username: renato
      - password: 2037Amok@
    """
    users = _get_users()
    if users:
        logger.info(f"Users already configured ({len(users)} user(s) found), skipping initialization")
        return

    logger.info("No users found — creating default user 'renato'")
    pw_hash, pw_salt = hash_password("2037Amok@")
    users["renato"] = {
        "password_hash": pw_hash,
        "salt": pw_salt,
    }
    _save_users(users)
    logger.info("Default user 'renato' created successfully")


def require_auth() -> None:
    """Streamlit authentication gate.

    Call once at the top of the Streamlit app (after st.set_page_config).
    If the user is not authenticated, renders a login form and calls st.stop().

    Login flow (avoids "Bad delta path" caused by login→app widget-tree switch):

    Phase 1 — same session as the login click:
      The on_click callback validates credentials, issues a short-lived token,
      and stores it in session_state["_needs_reload"]. On the next rerun this
      block reads the token, embeds it in the URL via JavaScript, and navigates
      there (= hard reload with token). The old Streamlit session ends.

    Phase 2 — new session after the reload:
      st.query_params contains the token. We consume it, set authenticated=True,
      and call st.rerun() (safe because no UI has been rendered yet). The
      following rerun returns immediately and the full app renders from scratch
      — no delta mismatch, no "Bad delta path" error.
    """
    init_default_users()

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.username = None

    # Phase 1: execute the hard reload with the auth token embedded in the URL.
    # _needs_reload holds the token string (not just True) so no extra
    # session-state key is needed.
    if st.session_state.get("_needs_reload"):
        token = st.session_state.pop("_needs_reload")
        # token_urlsafe produces only base64url chars (A-Z a-z 0-9 - _),
        # safe to embed directly in a JS string literal.
        st.components.v1.html(
            f"""<script>
                const u = new URL(window.parent.location.href);
                u.searchParams.set('_mpt_auth', '{token}');
                window.parent.location.href = u.toString();
            </script>""",
            height=0,
        )
        st.stop()

    # Phase 2: new session after the reload — consume the token from the URL.
    _mpt_auth = st.query_params.get("_mpt_auth")
    if _mpt_auth and not st.session_state.authenticated:
        del st.query_params["_mpt_auth"]
        username = _consume_auth_token(_mpt_auth)
        if username:
            st.session_state.authenticated = True
            st.session_state.username = username
            logger.info(f"User '{username}' authenticated via reload token")
            # Rerun to strip the token from the browser URL before rendering.
            # No UI has been rendered yet at this point, so st.rerun() is safe.
            st.rerun()
        else:
            st.session_state._login_error = "Sessão expirada. Faça login novamente."

    if st.session_state.authenticated:
        return

    # --- Login page ---
    st.title(":lock: MoneyPrinterTurbo")
    st.caption("Faça login para continuar")

    error_msg = st.session_state.pop("_login_error", None)
    if error_msg:
        st.error(error_msg)

    st.text_input(
        "Usuário", placeholder="Digite seu usuário", key="auth_username"
    )
    st.text_input(
        "Senha", type="password", placeholder="Digite sua senha", key="auth_password"
    )

    def _handle_login():
        """on_click callback — runs BEFORE the script body rerun."""
        u = st.session_state.get("auth_username", "")
        p = st.session_state.get("auth_password", "")
        if not u or not p:
            st.session_state._login_error = "Preencha usuário e senha."
        elif check_credentials(u, p):
            token = _issue_auth_token(u)
            # Store the token in session_state so Phase 1 can embed it in the
            # URL on the next rerun (before the hard reload).
            st.session_state._needs_reload = token
            logger.info(f"User '{u}' login initiated")
        else:
            st.session_state._login_error = "Usuário ou senha inválidos."

    st.button(
        "Entrar",
        use_container_width=True,
        key="auth_login_btn",
        on_click=_handle_login,
    )

    st.stop()
