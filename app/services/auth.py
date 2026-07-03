"""
Authentication service for MoneyPrinterTurbo WebUI.

Provides password hashing (PBKDF2 + SHA-256), credential verification,
default user initialization, and a Streamlit authentication gate.
"""

import hashlib
import secrets

import streamlit as st
from loguru import logger

from app.config import config


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
    """Return the users dictionary from config, or an empty dict.

    Reads directly from config._cfg so runtime updates are visible,
    unlike the module-level ``config.users`` snapshot.
    """
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
    """
    # Initialize default users on first run
    init_default_users()

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.username = None

    if st.session_state.authenticated:
        return

    # --- Login page ---
    st.title(":lock: MoneyPrinterTurbo")
    st.caption("Faça login para continuar")

    # Show any previous login error, then clear it so it doesn't persist
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
        """on_click callback — runs BEFORE the script body, so session state
        mutations are visible immediately without needing st.rerun()."""
        u = st.session_state.get("auth_username", "")
        p = st.session_state.get("auth_password", "")
        if not u or not p:
            st.session_state._login_error = "Preencha usuário e senha."
        elif check_credentials(u, p):
            st.session_state.authenticated = True
            st.session_state.username = u
            st.session_state._login_error = None
            logger.info(f"User '{u}' logged in successfully")
        else:
            st.session_state._login_error = "Usuário ou senha inválidos."

    st.button(
        "Entrar",
        use_container_width=True,
        key="auth_login_btn",
        on_click=_handle_login,
    )

    st.stop()
