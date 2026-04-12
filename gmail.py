"""Gmail API integration module for the Gmail-to-Telegram 2FA relay bot.

Handles OAuth2 authentication, mailbox watching via Pub/Sub, message
fetching, and message archiving through the Gmail API.
"""

import base64
import logging
import os
from datetime import datetime, timezone

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
PUBSUB_TOPIC_NAME = os.environ.get("PUBSUB_TOPIC_NAME", "")
APP_HOSTNAME = os.environ.get("APP_HOSTNAME", "")
WEB_PORT = os.environ.get("WEB_PORT", "8080")

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://mail.google.com/",
]

REDIRECT_URI = f"{APP_HOSTNAME}/oauth/callback"

CLIENT_CONFIG = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [REDIRECT_URI],
    }
}


class TokenRefreshError(Exception):
    """Raised when an OAuth2 token refresh fails."""


def _is_not_found_error(exc: Exception) -> bool:
    """Return ``True`` when the Gmail API error is an HTTP 404."""
    if isinstance(exc, HttpError):
        return exc.resp.status == 404
    error_str = str(exc)
    return "404" in error_str or "notFound" in error_str


def _decode_base64url(data: str) -> str:
    """Decode a base64url-encoded string to UTF-8 text.

    Gmail encodes message body parts using URL-safe base64 without padding.

    Args:
        data: Base64url-encoded string from the Gmail API.

    Returns:
        The decoded UTF-8 string.
    """
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")


def _get_header(headers: list[dict], name: str) -> str:
    """Extract a header value from a list of Gmail message headers.

    Args:
        headers: List of header dicts with ``name`` and ``value`` keys.
        name: Case-insensitive header name to look up.

    Returns:
        The header value, or an empty string if not found.
    """
    lower_name = name.lower()
    for header in headers:
        if header.get("name", "").lower() == lower_name:
            return header.get("value", "")
    return ""


def _extract_body(payload: dict) -> str:
    """Extract the plain-text (preferred) or HTML body from a message payload.

    Recursively walks the MIME part tree looking for ``text/plain`` first,
    falling back to ``text/html`` if no plain-text part is found.

    Args:
        payload: The ``payload`` object from a Gmail API message resource.

    Returns:
        The decoded message body text, or an empty string if none found.
    """
    parts = payload.get("parts", [])

    if not parts:
        mime_type = payload.get("mimeType", "")
        body_data = payload.get("body", {}).get("data", "")
        if body_data and mime_type in ("text/plain", "text/html"):
            return _decode_base64url(body_data)
        return ""

    plain_text = ""
    html_text = ""

    for part in parts:
        mime_type = part.get("mimeType", "")

        if mime_type == "text/plain":
            body_data = part.get("body", {}).get("data", "")
            if body_data:
                plain_text = _decode_base64url(body_data)
        elif mime_type == "text/html":
            body_data = part.get("body", {}).get("data", "")
            if body_data:
                html_text = _decode_base64url(body_data)
        elif mime_type.startswith("multipart/"):
            nested = _extract_body(part)
            if nested:
                if "text/plain" in (
                    p.get("mimeType", "") for p in part.get("parts", [])
                ):
                    plain_text = plain_text or nested
                else:
                    html_text = html_text or nested

    return plain_text or html_text


def generate_auth_url(state: str) -> str:
    """Generate an OAuth2 authorization URL for Gmail access.

    Uses offline access type and forces the approval prompt so a refresh
    token is always returned.

    Args:
        state: An opaque state string for CSRF protection.

    Returns:
        The full authorization URL the user should be redirected to.
    """
    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI

    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        state=state,
    )
    return auth_url


def exchange_code(code: str) -> tuple[str, str, str, str]:
    """Exchange an authorization code for OAuth2 tokens.

    After obtaining tokens, fetches the authenticated user's email address
    from the Gmail API profile.

    Args:
        code: The authorization code returned by Google's OAuth2 callback.

    Returns:
        A tuple of (email, refresh_token, access_token, token_expiry_iso).

    Raises:
        ValueError: If the token exchange does not return a refresh token.
    """
    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI
    flow.fetch_token(code=code)

    credentials = flow.credentials

    if not credentials.refresh_token:
        raise ValueError(
            "No refresh token received. Ensure access_type='offline' and "
            "prompt='consent' are set."
        )

    service = build("gmail", "v1", credentials=credentials)
    profile = service.users().getProfile(userId="me").execute()
    email = profile["emailAddress"]

    token_expiry_iso = ""
    if credentials.expiry:
        expiry_utc = credentials.expiry.replace(tzinfo=timezone.utc)
        token_expiry_iso = expiry_utc.isoformat()

    logger.info("Exchanged auth code for account %s", email)

    return (
        email,
        credentials.refresh_token,
        credentials.token,
        token_expiry_iso,
    )


def get_gmail_service(
    email: str,
    refresh_token: str,
    access_token: str | None,
    token_expiry: str | None,
) -> tuple:
    """Build an authorized Gmail API service instance.

    If the access token is missing or expired, it is refreshed
    automatically using the refresh token.

    Args:
        email: Gmail address (used for logging).
        refresh_token: OAuth2 refresh token.
        access_token: Current access token, or ``None``.
        token_expiry: ISO-8601 expiry timestamp, or ``None``.

    Returns:
        A tuple of (service, credentials) where *service* is a Gmail API
        resource and *credentials* is the (possibly refreshed)
        :class:`google.oauth2.credentials.Credentials`.

    Raises:
        TokenRefreshError: If the token cannot be refreshed.
    """
    expiry = None
    if token_expiry:
        try:
            expiry = datetime.fromisoformat(token_expiry)
            if expiry.tzinfo is not None:
                expiry = expiry.replace(tzinfo=None)
        except ValueError:
            logger.warning(
                "Could not parse token_expiry '%s' for %s", token_expiry, email
            )

    credentials = Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=SCOPES,
        expiry=expiry,
    )

    if not credentials.valid:
        try:
            credentials.refresh(Request())
            logger.debug("Refreshed access token for %s", email)
        except RefreshError as exc:
            logger.error("Token refresh failed for %s: %s", email, exc)
            raise TokenRefreshError(
                f"Failed to refresh token for {email}: {exc}"
            ) from exc

    service = build("gmail", "v1", credentials=credentials)
    return service, credentials


def watch_mailbox(service, email: str) -> str:
    """Subscribe a mailbox to Gmail push notifications via Pub/Sub.

    Args:
        service: An authorized Gmail API service instance.
        email: Gmail address of the account.

    Returns:
        The ``historyId`` from the watch response, representing the
        starting point for incremental history sync.
    """
    topic = f"projects/{GCP_PROJECT_ID}/topics/{PUBSUB_TOPIC_NAME}"

    request_body = {
        "topicName": topic,
        "labelIds": ["INBOX"],
    }

    response = (
        service.users().watch(userId=email, body=request_body).execute()
    )
    history_id = str(response["historyId"])
    logger.info(
        "Watching mailbox for %s (historyId=%s, topic=%s)",
        email,
        history_id,
        topic,
    )
    return history_id


def stop_watch(service, email: str) -> None:
    """Stop Gmail push notifications for a mailbox.

    Args:
        service: An authorized Gmail API service instance.
        email: Gmail address of the account.
    """
    service.users().stop(userId=email).execute()
    logger.info("Stopped watching mailbox for %s", email)


def fetch_new_messages(
    service, email: str, history_id: str
) -> list[dict]:
    """Fetch new messages added since a given history ID.

    Uses the Gmail ``users.history.list`` API with
    ``historyTypes=['messageAdded']`` to discover newly arrived messages,
    then fetches the full content for each one.

    Args:
        service: An authorized Gmail API service instance.
        email: Gmail address of the account.
        history_id: The history ID to start listing from.

    Returns:
        A list of dicts, each containing ``message_id``, ``subject``,
        ``body``, and ``from_address`` keys.
    """
    messages = []
    seen_ids: set[str] = set()

    try:
        page_token = None
        while True:
            kwargs: dict = {
                "userId": email,
                "startHistoryId": history_id,
                "historyTypes": ["messageAdded"],
            }
            if page_token:
                kwargs["pageToken"] = page_token

            response = service.users().history().list(**kwargs).execute()

            for record in response.get("history", []):
                for added in record.get("messagesAdded", []):
                    msg_id = added["message"]["id"]
                    if msg_id not in seen_ids:
                        seen_ids.add(msg_id)

            page_token = response.get("nextPageToken")
            if not page_token:
                break

    except Exception as exc:
        if _is_not_found_error(exc):
            logger.warning(
                "History ID %s not found for %s; may have expired",
                history_id,
                email,
            )
            return []
        raise

    for msg_id in seen_ids:
        try:
            msg = (
                service.users()
                .messages()
                .get(userId=email, id=msg_id, format="full")
                .execute()
            )

            payload = msg.get("payload", {})
            headers = payload.get("headers", [])

            subject = _get_header(headers, "Subject")
            from_address = _get_header(headers, "From")
            body = _extract_body(payload)

            messages.append(
                {
                    "message_id": msg_id,
                    "subject": subject,
                    "body": body,
                    "from_address": from_address,
                }
            )
        except Exception as exc:
            if _is_not_found_error(exc):
                logger.info(
                    "Skipping message %s for %s because it no longer exists",
                    msg_id,
                    email,
                )
                continue

            logger.exception("Failed to fetch message %s for %s", msg_id, email)

    logger.info(
        "Fetched %d new message(s) for %s since historyId=%s",
        len(messages),
        email,
        history_id,
    )
    return messages


def archive_message(service, email: str, message_id: str) -> None:
    """Archive a message by removing the INBOX label.

    Args:
        service: An authorized Gmail API service instance.
        email: Gmail address of the account.
        message_id: The Gmail message ID to archive.
    """
    service.users().messages().modify(
        userId=email,
        id=message_id,
        body={"removeLabelIds": ["INBOX"]},
    ).execute()
    logger.info("Archived message %s for %s", message_id, email)
