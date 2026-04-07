"""Main orchestrator for the Gmail-to-Telegram 2FA relay bot."""

import asyncio
import json
import logging
import os
import re
import signal
import sys

from dotenv import load_dotenv

load_dotenv()

import database
import gmail
import llm
import telegram_bot
import web_server

from google.cloud import pubsub_v1

logger = logging.getLogger(__name__)

GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID", "")
PUBSUB_SUBSCRIPTION_NAME = os.getenv("PUBSUB_SUBSCRIPTION_NAME", "")
ENABLE_PRE_FILTER = os.getenv("ENABLE_PRE_FILTER", "false").lower() == "true"
ARCHIVE_PROCESSED_EMAILS = os.getenv("ARCHIVE_PROCESSED_EMAILS", "false").lower() == "true"

PUBSUB_CALLBACK_TIMEOUT = 120

PRE_FILTER_PATTERN = re.compile(
    r"(code|verification|verify|login|sign\s*in|authenticate|2fa|mfa|password|otp)",
    re.IGNORECASE,
)


def passes_pre_filter(subject: str, body: str) -> bool:
    """Check if subject or body contains 2FA-related keywords."""
    return bool(PRE_FILTER_PATTERN.search(subject) or PRE_FILTER_PATTERN.search(body))


async def _process_message(bot, email_address: str, msg: dict) -> None:
    """Process a single email message: pre-filter, extract 2FA, notify, archive."""
    subject = msg.get("subject", "")
    body = msg.get("body", "")
    message_id = msg.get("message_id", "")

    if ENABLE_PRE_FILTER and not passes_pre_filter(subject, body):
        logger.debug("Pre-filter rejected message %s for %s", message_id, email_address)
        return

    result = await llm.extract_2fa_from_email(subject, body)
    if result is None:
        logger.debug("No 2FA content in message %s for %s", message_id, email_address)
        return

    await telegram_bot.send_2fa_message(
        bot,
        email_address,
        result.get("summary", ""),
        result.get("code"),
        result.get("link"),
    )

    if ARCHIVE_PROCESSED_EMAILS:
        account = await database.get_account(email_address)
        if account:
            try:
                service, _ = gmail.get_gmail_service(
                    email_address,
                    account["refresh_token"],
                    account.get("access_token"),
                    account.get("token_expiry"),
                )
                gmail.archive_message(service, email_address, message_id)
                logger.info("Archived message %s for %s", message_id, email_address)
            except Exception:
                logger.exception("Failed to archive message %s for %s", message_id, email_address)


async def _handle_pubsub_notification(bot, email_address: str, history_id: str) -> None:
    """Handle a single Pub/Sub push notification for an account."""
    account = await database.get_account(email_address)
    if account is None:
        logger.warning("No account found for %s, skipping", email_address)
        return
    if not account.get("enabled", 1):
        logger.info("Account %s is disabled, skipping", email_address)
        return

    stored_history_id = account.get("history_id")
    if stored_history_id is None:
        logger.warning("No stored history_id for %s, updating and skipping", email_address)
        await database.update_history_id(email_address, history_id)
        return

    try:
        service, creds = gmail.get_gmail_service(
            email_address,
            account["refresh_token"],
            account.get("access_token"),
            account.get("token_expiry"),
        )

        if creds.token != account.get("access_token"):
            expiry_iso = creds.expiry.isoformat() if creds.expiry else None
            await database.update_tokens(email_address, creds.token, expiry_iso)

        messages = gmail.fetch_new_messages(service, email_address, stored_history_id)
        await database.update_history_id(email_address, history_id)

        for msg in messages:
            try:
                await _process_message(bot, email_address, msg)
            except Exception:
                logger.exception(
                    "Error processing message %s for %s",
                    msg.get("message_id", "unknown"),
                    email_address,
                )

    except gmail.TokenRefreshError:
        logger.error("Token refresh failed for %s, disabling account", email_address)
        await database.disable_account(email_address)
        await telegram_bot.send_alert_message(
            bot,
            f"Token refresh failed for {email_address}. "
            "Account has been disabled. Please re-add it with /add.",
        )
    except Exception:
        logger.exception("Error handling notification for %s", email_address)


async def _start_pubsub_listener(bot, shutdown_event: asyncio.Event) -> None:
    """Start the Pub/Sub streaming pull listener with retry and exponential backoff."""
    subscription_path = f"projects/{GCP_PROJECT_ID}/subscriptions/{PUBSUB_SUBSCRIPTION_NAME}"
    backoff = 1
    max_backoff = 60

    while not shutdown_event.is_set():
        try:
            subscriber = pubsub_v1.SubscriberClient()
            logger.info("Starting Pub/Sub listener on %s", subscription_path)

            def callback(message):
                try:
                    data = json.loads(message.data.decode("utf-8"))
                    email_address = data.get("emailAddress", "")
                    history_id = str(data.get("historyId", ""))

                    if not email_address or not history_id:
                        logger.warning("Invalid Pub/Sub message data: %s", data)
                        message.ack()
                        return

                    logger.info(
                        "Pub/Sub notification for %s (historyId: %s)",
                        email_address,
                        history_id,
                    )

                    loop = asyncio.get_event_loop()
                    future = asyncio.run_coroutine_threadsafe(
                        _handle_pubsub_notification(bot, email_address, history_id),
                        loop,
                    )
                    future.result(timeout=PUBSUB_CALLBACK_TIMEOUT)

                except Exception:
                    logger.exception("Error in Pub/Sub callback")
                finally:
                    message.ack()

            streaming_pull_future = subscriber.subscribe(subscription_path, callback=callback)
            backoff = 1

            while not shutdown_event.is_set():
                try:
                    await asyncio.sleep(1)
                    if streaming_pull_future.done():
                        streaming_pull_future.result()
                        break
                except Exception:
                    break

            streaming_pull_future.cancel()
            try:
                streaming_pull_future.result(timeout=5)
            except Exception:
                pass
            subscriber.close()

        except Exception:
            logger.exception("Pub/Sub listener error, retrying in %ds", backoff)
            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=backoff)
                break
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, max_backoff)

    logger.info("Pub/Sub listener stopped")


async def _register_watches(bot) -> None:
    """Re-register Gmail watches for all enabled accounts on startup."""
    accounts = await database.get_all_accounts()
    for account in accounts:
        email = account["email_address"]
        try:
            service, creds = gmail.get_gmail_service(
                email,
                account["refresh_token"],
                account.get("access_token"),
                account.get("token_expiry"),
            )
            if creds.token != account.get("access_token"):
                expiry_iso = creds.expiry.isoformat() if creds.expiry else None
                await database.update_tokens(email, creds.token, expiry_iso)

            new_history_id = gmail.watch_mailbox(service, email)
            await database.update_history_id(email, new_history_id)
            logger.info("Re-registered watch for %s", email)

        except gmail.TokenRefreshError:
            logger.error("Token refresh failed for %s during watch registration", email)
            await database.disable_account(email)
            await telegram_bot.send_alert_message(
                bot,
                f"Token refresh failed for {email} during startup. "
                "Account has been disabled. Please re-add it with /add.",
            )
        except Exception:
            logger.exception("Failed to register watch for %s", email)


async def main() -> None:
    """Main entry point: start all components and run until interrupted."""
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_event.set)

    await database.init_db()

    application = telegram_bot.create_bot_application()
    await application.initialize()

    web_server.set_bot(application.bot)
    runner = await web_server.start_web_server()

    await _register_watches(application.bot)

    await application.start()
    await application.updater.start_polling()

    pubsub_task = asyncio.create_task(
        _start_pubsub_listener(application.bot, shutdown_event)
    )

    logger.info("Bot is running. Press Ctrl+C to stop.")

    await shutdown_event.wait()
    logger.info("Shutdown signal received, cleaning up...")

    pubsub_task.cancel()
    try:
        await pubsub_task
    except asyncio.CancelledError:
        pass

    await application.updater.stop()
    await application.stop()
    await web_server.stop_web_server(runner)
    await application.shutdown()

    logger.info("Shutdown complete")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    asyncio.run(main())
