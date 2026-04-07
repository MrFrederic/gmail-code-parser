"""Async web server module for handling OAuth callbacks.

Provides an aiohttp-based web server with a single route that processes
Google OAuth2 callback requests, persists account credentials, and sets
up Gmail push-notification watches.
"""

import logging
import os

from aiohttp import web

import database
import gmail
import telegram_bot

logger = logging.getLogger(__name__)

WEB_PORT = int(os.environ.get("WEB_PORT", "8080"))

_bot = None

_HTML_STYLE = (
    "<style>"
    "body{margin:0;padding:0;font-family:system-ui,-apple-system,sans-serif;"
    "background:#f0f2f5;display:flex;align-items:center;justify-content:center;"
    "min-height:100vh}"
    ".card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);"
    "padding:48px;max-width:440px;text-align:center}"
    "h1{margin:0 0 12px;font-size:24px}"
    "p{color:#555;font-size:16px;line-height:1.5;margin:0}"
    ".icon{font-size:48px;margin-bottom:16px}"
    "</style>"
)

_SUCCESS_HTML = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Account Connected</title>{style}</head>"
    "<body><div class='card'>"
    "<div class='icon'>✅</div>"
    "<h1>Account Connected Successfully!</h1>"
    "<p>You can close this window.</p>"
    "</div></body></html>"
).format(style=_HTML_STYLE)

_ERROR_400_HTML = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Bad Request</title>{style}</head>"
    "<body><div class='card'>"
    "<div class='icon'>⚠️</div>"
    "<h1>Bad Request</h1>"
    "<p>Invalid or expired OAuth state. Please try again from Telegram.</p>"
    "</div></body></html>"
).format(style=_HTML_STYLE)

_ERROR_500_HTML = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Server Error</title>{style}</head>"
    "<body><div class='card'>"
    "<div class='icon'>❌</div>"
    "<h1>Something Went Wrong</h1>"
    "<p>An internal error occurred while connecting your account. "
    "Please try again later.</p>"
    "</div></body></html>"
).format(style=_HTML_STYLE)


def set_bot(bot) -> None:
    """Set the Telegram bot reference used by the OAuth callback handler.

    Args:
        bot: A ``telegram.Bot`` instance.
    """
    global _bot
    _bot = bot


async def _handle_oauth_callback(request: web.Request) -> web.Response:
    """Handle the GET /oauth/callback route.

    Validates the OAuth state, exchanges the authorization code for
    tokens, persists the new account, starts a Gmail mailbox watch,
    and notifies the user via Telegram.
    """
    code = request.query.get("code")
    state = request.query.get("state")

    if not code or not state:
        logger.warning("OAuth callback missing code or state parameter")
        return web.Response(
            text=_ERROR_400_HTML, content_type="text/html", status=400
        )

    valid = await database.validate_oauth_state(state)
    if not valid:
        logger.warning("OAuth callback with invalid state: %s", state)
        return web.Response(
            text=_ERROR_400_HTML, content_type="text/html", status=400
        )

    try:
        email, refresh_token, access_token, token_expiry = (
            gmail.exchange_code(code)
        )

        await database.add_account(
            email, refresh_token, access_token, token_expiry, None
        )

        service, _ = gmail.get_gmail_service(
            email, refresh_token, access_token, token_expiry
        )
        history_id = gmail.watch_mailbox(service, email)
        await database.update_history_id(email, history_id)

        logger.info("Successfully connected account %s", email)

        if _bot:
            try:
                await telegram_bot.send_success_message(
                    _bot,
                    f"✅ Successfully connected and monitoring: "
                    f"<code>{email}</code>.",
                )
            except Exception:
                logger.exception(
                    "Failed to send Telegram success message for %s", email
                )

        return web.Response(
            text=_SUCCESS_HTML, content_type="text/html", status=200
        )

    except Exception:
        logger.exception("Error during OAuth callback processing")

        if _bot:
            try:
                await telegram_bot.send_error_message(
                    _bot,
                    "Failed to connect Gmail account during OAuth callback. "
                    "Check the server logs for details.",
                )
            except Exception:
                logger.exception(
                    "Failed to send Telegram error message"
                )

        return web.Response(
            text=_ERROR_500_HTML, content_type="text/html", status=500
        )


async def start_web_server() -> web.AppRunner:
    """Create and start the aiohttp web server.

    Returns:
        The :class:`aiohttp.web.AppRunner` instance so the caller can
        clean it up later via :func:`stop_web_server`.
    """
    app = web.Application()
    app.router.add_get("/oauth/callback", _handle_oauth_callback)

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, "0.0.0.0", WEB_PORT)
    await site.start()

    logger.info("Web server started on port %d", WEB_PORT)
    return runner


async def stop_web_server(runner: web.AppRunner) -> None:
    """Shut down the web server and release its resources.

    Args:
        runner: The :class:`aiohttp.web.AppRunner` returned by
            :func:`start_web_server`.
    """
    await runner.cleanup()
    logger.info("Web server stopped")
