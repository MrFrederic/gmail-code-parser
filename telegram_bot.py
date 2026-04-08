"""Telegram bot module for the Gmail-to-Telegram 2FA relay bot.

Provides command handlers for managing Gmail accounts and standalone
functions for sending formatted 2FA notifications to the authorised
Telegram chat.
"""

import html
import logging
import os
import secrets
from email.utils import parseaddr
from functools import wraps
from typing import Callable, Coroutine
from urllib.parse import urlparse

from telegram import (
    Bot,
    CopyTextButton,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

import database
import gmail

logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
ALLOWED_CHAT_ID = os.environ.get("ALLOWED_CHAT_ID", "")


def _get_allowed_chat_id() -> int:
    """Return ALLOWED_CHAT_ID as an integer.

    Raises:
        ValueError: If the environment variable is missing or not numeric.
    """
    if not ALLOWED_CHAT_ID:
        raise ValueError(
            "ALLOWED_CHAT_ID environment variable is not set or empty"
        )
    return int(ALLOWED_CHAT_ID)


def _authorised(
    func: Callable[..., Coroutine],
) -> Callable[..., Coroutine]:
    """Decorator that restricts a handler to ALLOWED_CHAT_ID.

    Messages from any other chat are silently ignored.
    """

    @wraps(func)
    async def wrapper(
        update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if update.effective_chat is None:
            return
        if str(update.effective_chat.id) != ALLOWED_CHAT_ID:
            logger.warning(
                "Unauthorised access attempt from chat %s",
                update.effective_chat.id,
            )
            return
        await func(update, context)

    return wrapper


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _get_help_text() -> str:
    """Return the up-to-date help text shown by /start and /help."""
    return (
        "👋 <b>Welcome to the Gmail 2FA Relay Bot!</b>\n\n"
        "I forward two-factor authentication codes and verification "
        "links from your Gmail accounts straight to this chat. "
        "Codes arrive as tap-to-copy buttons, and links appear as "
        "inline action buttons inside each account's topic.\n\n"
        "<b>Commands:</b>\n"
        "/add — Connect a new Gmail account\n"
        "/remove — Disconnect a Gmail account\n"
        "/list — Show connected accounts\n"
        "/help — Show this help message"
    )


@_authorised
async def start_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the /start command with a welcome message."""
    await update.message.reply_text(  # type: ignore[union-attr]
        text=_get_help_text(),
        parse_mode=ParseMode.HTML,
    )


@_authorised
async def help_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the /help command with usage instructions."""
    await update.message.reply_text(  # type: ignore[union-attr]
        text=_get_help_text(),
        parse_mode=ParseMode.HTML,
    )


@_authorised
async def add_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the /add command — generate an OAuth URL for account linking."""
    state = secrets.token_urlsafe(32)
    await database.save_oauth_state(state)

    auth_url = gmail.generate_auth_url(state)

    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    text="Login to Google",
                    url=auth_url,
                    icon_custom_emoji_id="5325520389160341366",
                )
            ]
        ]
    )

    await update.message.reply_text(  # type: ignore[union-attr]
        "Click the button below to connect your Gmail account:",
        reply_markup=keyboard,
    )


@_authorised
async def remove_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the /remove command — show accounts available for removal."""
    accounts = await database.get_all_accounts()

    if not accounts:
        await update.message.reply_text(  # type: ignore[union-attr]
            "No accounts connected."
        )
        return

    buttons = [
        [
            InlineKeyboardButton(
                text=account["email_address"],
                callback_data=f"remove_account:{account['email_address']}",
            )
        ]
        for account in accounts
    ]

    keyboard = InlineKeyboardMarkup(buttons)
    await update.message.reply_text(  # type: ignore[union-attr]
        "Select an account to remove:",
        reply_markup=keyboard,
    )


@_authorised
async def list_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the /list command — display all monitored email addresses."""
    accounts = await database.get_all_accounts()

    if not accounts:
        await update.message.reply_text(  # type: ignore[union-attr]
            "No accounts connected."
        )
        return

    lines = ["<b>Connected accounts:</b>\n"]
    for idx, account in enumerate(accounts, start=1):
        email = html.escape(account["email_address"])
        lines.append(f"{idx}. {email}")

    await update.message.reply_text(  # type: ignore[union-attr]
        "\n".join(lines),
        parse_mode=ParseMode.HTML,
    )


@_authorised
async def remove_account_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle inline-keyboard callback for account removal."""
    query = update.callback_query
    await query.answer()  # type: ignore[union-attr]

    email = query.data.split(":", 1)[1]  # type: ignore[union-attr]

    account = await database.get_account(email)
    if account is None:
        await query.edit_message_text(  # type: ignore[union-attr]
            f"Account {html.escape(email)} not found.",
            parse_mode=ParseMode.HTML,
        )
        return

    try:
        service, _ = gmail.get_gmail_service(
            email,
            account["refresh_token"],
            account.get("access_token"),
            account.get("token_expiry"),
        )
        gmail.stop_watch(service, email)
    except Exception:
        logger.exception("Failed to stop watch for %s during removal", email)

    await database.remove_account(email)

    try:
        await close_account_topic(context.bot, email)
    except Exception:
        logger.exception("Failed to close topic for %s during removal", email)

    await query.edit_message_text(  # type: ignore[union-attr]
        f"✅ Account <b>{html.escape(email)}</b> has been removed.",
        parse_mode=ParseMode.HTML,
    )
    logger.info("Removed account %s via /remove", email)


# ---------------------------------------------------------------------------
# Forum-topic helpers
# ---------------------------------------------------------------------------


async def get_or_create_topic(bot: Bot, email: str) -> int:
    """Return the forum-topic thread ID for *email*, creating one if needed.

    If a topic was previously created for this email (even if the account
    was since removed), it is reused and reopened.  Otherwise a brand-new
    topic is created via the Telegram API and its ID is persisted.

    Args:
        bot: A ``telegram.Bot`` instance.
        email: Gmail address that identifies the topic.

    Returns:
        The ``message_thread_id`` to use with ``send_message``.
    """
    chat_id = _get_allowed_chat_id()

    thread_id = await database.get_topic_thread_id(email)
    if thread_id is not None:
        try:
            await bot.reopen_forum_topic(
                chat_id=chat_id, message_thread_id=thread_id
            )
        except Exception:
            # Already open or other non-critical error — carry on.
            pass
        return thread_id

    topic = await bot.create_forum_topic(chat_id=chat_id, name=email)
    await database.save_topic_thread_id(email, topic.message_thread_id)
    logger.info(
        "Created forum topic %d for %s", topic.message_thread_id, email
    )
    return topic.message_thread_id


async def close_account_topic(bot: Bot, email: str) -> None:
    """Close (archive) the forum topic associated with *email*.

    Does nothing if the email has no stored topic mapping.

    Args:
        bot: A ``telegram.Bot`` instance.
        email: Gmail address whose topic should be closed.
    """
    thread_id = await database.get_topic_thread_id(email)
    if thread_id is None:
        return

    chat_id = _get_allowed_chat_id()
    try:
        await bot.close_forum_topic(
            chat_id=chat_id, message_thread_id=thread_id
        )
        logger.info("Closed forum topic %d for %s", thread_id, email)
    except Exception:
        logger.exception("Failed to close topic for %s", email)


# ---------------------------------------------------------------------------
# Standalone message-sending functions
# ---------------------------------------------------------------------------


def _normalise_link_label(link_label: str | None) -> str:
    """Return a short, Telegram-friendly label for a verification link."""
    cleaned = " ".join((link_label or "").split())
    if not cleaned:
        return "Open link"

    if cleaned.casefold() in {
        "verify",
        "confirm",
        "verify / confirm",
        "open",
        "open link",
        "continue",
    }:
        return "Open link"

    if len(cleaned) > 32:
        return f"{cleaned[:29].rstrip()}..."

    return cleaned


def _normalise_link_url(link: str | None) -> str | None:
    """Return a safe http(s) verification link or ``None`` if invalid."""
    cleaned = (link or "").strip()
    if not cleaned:
        return None

    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    return cleaned


async def send_2fa_message(
    bot: Bot,
    email: str,
    summary: str,
    code: str | None,
    link: str | None,
    link_label: str | None = None,
    sender_email: str | None = None,
) -> None:
    """Send a formatted 2FA notification to the account's forum topic.

    The message is routed to the topic that corresponds to *email*; a
    new topic is created automatically if one does not yet exist.

    Args:
        bot: A ``telegram.Bot`` instance.
        email: The connected Gmail account that received the message.
        summary: A human-readable summary of the 2FA email.
        code: The extracted verification code, or ``None``.
        link: The extracted verification link, or ``None``.
        link_label: Short LLM-generated button text describing the link action.
        sender_email: The sender address from the original email, if available.
    """
    chat_id = _get_allowed_chat_id()
    thread_id = await get_or_create_topic(bot, email)

    parsed_sender = parseaddr(sender_email or "")[1] or (sender_email or "")

    safe_link = _normalise_link_url(link)
    if link and safe_link is None:
        logger.warning("Skipping unsupported verification link for %s", email)

    parts: list[str] = []

    if parsed_sender:
        parts.append(
            f'<tg-emoji emoji-id="5325911231184278615">📨</tg-emoji> '
            f"<b>From:</b> {html.escape(parsed_sender)}"
        )

    if summary:
        if parts:
            parts.append("")
        parts.append(html.escape(summary))
    elif not parts:
        parts.append("Authentication request received")

    buttons: list[InlineKeyboardButton] = []

    if code:
        buttons.append(
            InlineKeyboardButton(
                text=code,
                copy_text=CopyTextButton(text=code),
            )
        )

    if safe_link:
        buttons.append(
            InlineKeyboardButton(
                text=_normalise_link_label(link_label),
                url=safe_link,
            )
        )

    reply_markup = InlineKeyboardMarkup([buttons]) if buttons else None

    await bot.send_message(
        chat_id=chat_id,
        message_thread_id=thread_id,
        text="\n".join(parts),
        parse_mode=ParseMode.HTML,
        reply_markup=reply_markup,
    )


async def send_error_message(bot: Bot, text: str) -> None:
    """Send an error notification to the authorised chat.

    Args:
        bot: A ``telegram.Bot`` instance.
        text: The error message text.
    """
    chat_id = _get_allowed_chat_id()
    await bot.send_message(
        chat_id=chat_id,
        text=f"❌ <b>Error</b>\n{html.escape(text)}",
        parse_mode=ParseMode.HTML,
    )


async def send_alert_message(bot: Bot, text: str) -> None:
    """Send an alert notification to the authorised chat.

    Args:
        bot: A ``telegram.Bot`` instance.
        text: The alert message text.
    """
    chat_id = _get_allowed_chat_id()
    await bot.send_message(
        chat_id=chat_id,
        text=f"⚠️ <b>Alert</b>\n{html.escape(text)}",
        parse_mode=ParseMode.HTML,
    )


async def send_success_message(bot: Bot, text: str) -> None:
    """Send a success notification to the authorised chat.

    Args:
        bot: A ``telegram.Bot`` instance.
        text: The success message text.
    """
    chat_id = _get_allowed_chat_id()
    await bot.send_message(
        chat_id=chat_id,
        text=f"✅ <b>Success</b>\n{html.escape(text)}",
        parse_mode=ParseMode.HTML,
    )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_bot_application() -> Application:
    """Create and configure the Telegram bot Application with all handlers.

    The caller is responsible for starting the application (e.g. via
    ``run_polling`` or integrating with an existing event loop).

    Returns:
        A fully configured ``telegram.ext.Application`` instance.
    """
    application = (
        Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    )

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("add", add_command))
    application.add_handler(CommandHandler("remove", remove_command))
    application.add_handler(CommandHandler("list", list_command))
    application.add_handler(
        CallbackQueryHandler(
            remove_account_callback, pattern=r"^remove_account:"
        )
    )

    logger.info("Telegram bot application created with all handlers")
    return application
