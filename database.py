"""Async SQLite database module for the Gmail-to-Telegram 2FA relay bot.

Manages account credentials, OAuth tokens, and OAuth state parameters
using aiosqlite for non-blocking database operations.
"""

import logging
import os
from datetime import datetime, timedelta, timezone

import aiosqlite

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/accounts.db")


async def _get_connection() -> aiosqlite.Connection:
    """Open a connection to the SQLite database with row factory enabled."""
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    return conn


async def init_db() -> None:
    """Create database tables if they do not already exist.

    Also ensures the parent directory for the database file is present.
    """
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)

    conn = await _get_connection()
    try:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                email_address  TEXT    UNIQUE NOT NULL,
                refresh_token  TEXT    NOT NULL,
                access_token   TEXT,
                token_expiry   TEXT,
                history_id     TEXT,
                enabled        INTEGER DEFAULT 1,
                created_at     TEXT    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_states (
                state      TEXT PRIMARY KEY,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await conn.commit()
        logger.info("Database initialised at %s", DB_PATH)
    finally:
        await conn.close()


async def add_account(
    email: str,
    refresh_token: str,
    access_token: str | None = None,
    token_expiry: str | None = None,
    history_id: str | None = None,
) -> None:
    """Insert a new account or update an existing one (upsert).

    Args:
        email: Gmail address to associate with the account.
        refresh_token: OAuth2 refresh token.
        access_token: Current OAuth2 access token.
        token_expiry: ISO-8601 expiry timestamp for the access token.
        history_id: Gmail history ID for incremental sync.
    """
    conn = await _get_connection()
    try:
        await conn.execute(
            """
            INSERT INTO accounts (email_address, refresh_token, access_token,
                                  token_expiry, history_id)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(email_address) DO UPDATE SET
                refresh_token = excluded.refresh_token,
                access_token  = excluded.access_token,
                token_expiry  = excluded.token_expiry,
                history_id    = excluded.history_id,
                enabled       = 1
            """,
            (email, refresh_token, access_token, token_expiry, history_id),
        )
        await conn.commit()
        logger.info("Upserted account %s", email)
    finally:
        await conn.close()


async def remove_account(email: str) -> None:
    """Delete an account by its email address.

    Args:
        email: Gmail address of the account to remove.
    """
    conn = await _get_connection()
    try:
        await conn.execute(
            "DELETE FROM accounts WHERE email_address = ?", (email,)
        )
        await conn.commit()
        logger.info("Removed account %s", email)
    finally:
        await conn.close()


async def get_account(email: str) -> dict | None:
    """Retrieve a single account by email address.

    Args:
        email: Gmail address to look up.

    Returns:
        A dictionary of the account row, or ``None`` if not found.
    """
    conn = await _get_connection()
    try:
        cursor = await conn.execute(
            "SELECT * FROM accounts WHERE email_address = ?", (email,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        await conn.close()


async def get_all_accounts() -> list[dict]:
    """Return all enabled accounts.

    Returns:
        A list of dictionaries, one per enabled account row.
    """
    conn = await _get_connection()
    try:
        cursor = await conn.execute(
            "SELECT * FROM accounts WHERE enabled = 1"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await conn.close()


async def update_tokens(
    email: str, access_token: str, token_expiry: str
) -> None:
    """Update the access token and its expiry for an account.

    Args:
        email: Gmail address of the account to update.
        access_token: New OAuth2 access token.
        token_expiry: ISO-8601 expiry timestamp for the new token.
    """
    conn = await _get_connection()
    try:
        await conn.execute(
            """
            UPDATE accounts
               SET access_token = ?, token_expiry = ?
             WHERE email_address = ?
            """,
            (access_token, token_expiry, email),
        )
        await conn.commit()
        logger.debug("Updated tokens for %s", email)
    finally:
        await conn.close()


async def update_history_id(email: str, history_id: str) -> None:
    """Update the Gmail history ID for an account.

    Args:
        email: Gmail address of the account to update.
        history_id: New Gmail history ID value.
    """
    conn = await _get_connection()
    try:
        await conn.execute(
            "UPDATE accounts SET history_id = ? WHERE email_address = ?",
            (history_id, email),
        )
        await conn.commit()
        logger.debug("Updated history_id for %s to %s", email, history_id)
    finally:
        await conn.close()


async def disable_account(email: str) -> None:
    """Disable an account by setting its ``enabled`` flag to 0.

    Args:
        email: Gmail address of the account to disable.
    """
    conn = await _get_connection()
    try:
        await conn.execute(
            "UPDATE accounts SET enabled = 0 WHERE email_address = ?",
            (email,),
        )
        await conn.commit()
        logger.info("Disabled account %s", email)
    finally:
        await conn.close()


async def save_oauth_state(state: str) -> None:
    """Persist an OAuth state parameter for later validation.

    Args:
        state: The random state string sent with the OAuth request.
    """
    conn = await _get_connection()
    try:
        await conn.execute(
            "INSERT INTO oauth_states (state) VALUES (?)", (state,)
        )
        await conn.commit()
        logger.debug("Saved OAuth state %s", state)
    finally:
        await conn.close()


async def validate_oauth_state(state: str) -> bool:
    """Check whether an OAuth state parameter is valid.

    If the state exists it is deleted (single-use) and ``True`` is returned.
    Otherwise ``False`` is returned.

    Args:
        state: The state string to validate.

    Returns:
        ``True`` if the state was found (and consumed), ``False`` otherwise.
    """
    conn = await _get_connection()
    try:
        cursor = await conn.execute(
            "SELECT state FROM oauth_states WHERE state = ?", (state,)
        )
        row = await cursor.fetchone()
        if row is None:
            return False
        await conn.execute(
            "DELETE FROM oauth_states WHERE state = ?", (state,)
        )
        await conn.commit()
        logger.debug("Validated and consumed OAuth state %s", state)
        return True
    finally:
        await conn.close()


async def cleanup_old_states(max_age_minutes: int = 30) -> None:
    """Remove OAuth states older than the specified age.

    Args:
        max_age_minutes: Maximum age in minutes before a state is considered
            expired.  Defaults to 30.
    """
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
    ).strftime("%Y-%m-%d %H:%M:%S")

    conn = await _get_connection()
    try:
        cursor = await conn.execute(
            "DELETE FROM oauth_states WHERE created_at < ?", (cutoff,)
        )
        await conn.commit()
        deleted = cursor.rowcount
        if deleted:
            logger.info("Cleaned up %d expired OAuth state(s)", deleted)
    finally:
        await conn.close()
