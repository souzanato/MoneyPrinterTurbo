"""
Authentication service for MoneyPrinterTurbo WebUI.

Provides password hashing (PBKDF2 + SHA-256), credential verification,
default user initialization, and a Streamlit authentication gate.
"""

import hashlib
import secrets

import streamlit as st
import streamlit.components.v1 as components
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

    with st.form("login_form", clear_on_submit=True):
        username = st.text_input("Usuário", placeholder="Digite seu usuário")
        password = st.text_input("Senha", type="password", placeholder="Digite sua senha")
        submitted = st.form_submit_button("Entrar", use_container_width=True)

        if submitted:
            if not username or not password:
                st.error("Preencha usuário e senha.")
            elif check_credentials(username, password):
                st.session_state.authenticated = True
                st.session_state.username = username
                logger.info(f"User '{username}' logged in successfully")
                # Use a full-page reload via JS instead of st.rerun() to avoid
                # the Streamlit 1.58 "Bad delta path index" frontend bug that
                # corrupts the WebSocket state after form submit + rerun.
                components.html(
                    "<script>window.parent.location.reload()</script>",
                    height=0,
                )
                st.stop()
            else:
                st.error("Usuário ou senha inválidos.")

    st.stop()
