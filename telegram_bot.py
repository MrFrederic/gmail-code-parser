"""Telegram bot module for the Gmail-to-Telegram 2FA relay bot.

Provides command handlers for managing Gmail accounts and standalone
functions for sending formatted 2FA notifications to the authorised
Telegram chat.
"""

import html
import logging
import os
import secrets
from functools import wraps
from typing import Callable, Coroutine

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
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


@_authorised
async def start_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the /start command with a welcome message."""
    text = (
        "👋 <b>Welcome to the Gmail 2FA Relay Bot!</b>\n\n"
        "I forward two-factor authentication codes and verification "
        "links from your Gmail accounts straight to this chat.\n\n"
        "<b>Commands:</b>\n"
        "/add — Connect a new Gmail account\n"
        "/remove — Disconnect a Gmail account\n"
        "/list — Show connected accounts"
    )
    await update.message.reply_text(  # type: ignore[union-attr]
        text=text,
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
                    text="🔗 Login to Google", url=auth_url
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

    await query.edit_message_text(  # type: ignore[union-attr]
        f"✅ Account <b>{html.escape(email)}</b> has been removed.",
        parse_mode=ParseMode.HTML,
    )
    logger.info("Removed account %s via /remove", email)


# ---------------------------------------------------------------------------
# Standalone message-sending functions
# ---------------------------------------------------------------------------


async def send_2fa_message(
    bot,
    email: str,
    summary: str,
    code: str | None,
    link: str | None,
) -> None:
    """Send a formatted 2FA notification to the authorised chat.

    Args:
        bot: A ``telegram.Bot`` instance.
        email: The Gmail address the message originated from.
        summary: A human-readable summary of the 2FA email.
        code: The extracted verification code, or ``None``.
        link: The extracted verification link, or ``None``.
    """
    chat_id = int(ALLOWED_CHAT_ID)

    parts = [
        f"📬 <b>{html.escape(email)}</b>\n",
        html.escape(summary),
    ]

    if code:
        parts.append(f"\n🔑 Code: <code>{html.escape(code)}</code>")

    reply_markup = None
    if link:
        reply_markup = InlineKeyboardMarkup(
            [[InlineKeyboardButton(text="🔗 Verify / Confirm", url=link)]]
        )

    await bot.send_message(
        chat_id=chat_id,
        text="\n".join(parts),
        parse_mode=ParseMode.HTML,
        reply_markup=reply_markup,
    )


async def send_error_message(bot, text: str) -> None:
    """Send an error notification to the authorised chat.

    Args:
        bot: A ``telegram.Bot`` instance.
        text: The error message text.
    """
    chat_id = int(ALLOWED_CHAT_ID)
    await bot.send_message(
        chat_id=chat_id,
        text=f"❌ <b>Error</b>\n{html.escape(text)}",
        parse_mode=ParseMode.HTML,
    )


async def send_alert_message(bot, text: str) -> None:
    """Send an alert notification to the authorised chat.

    Args:
        bot: A ``telegram.Bot`` instance.
        text: The alert message text.
    """
    chat_id = int(ALLOWED_CHAT_ID)
    await bot.send_message(
        chat_id=chat_id,
        text=f"⚠️ <b>Alert</b>\n{html.escape(text)}",
        parse_mode=ParseMode.HTML,
    )


async def send_success_message(bot, text: str) -> None:
    """Send a success notification to the authorised chat.

    Args:
        bot: A ``telegram.Bot`` instance.
        text: The success message text.
    """
    chat_id = int(ALLOWED_CHAT_ID)
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
