"""LLM integration module for extracting 2FA codes and links from emails.

Uses the OpenRouter API to send email content to a large language model
with a strict system prompt that returns structured JSON results.
"""

import json
import logging
import os
import re

import httpx

logger = logging.getLogger(__name__)

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "google/gemini-2.0-flash-001")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

if not OPENROUTER_API_KEY:
    logger.warning("OPENROUTER_API_KEY is not set; LLM calls will fail")

SYSTEM_PROMPT = """\
You are a strict authentication-email extraction assistant. Your ONLY job is to \
analyze an email and determine whether it is specifically about account access, \
such as sign-in, login, registration, signup, email verification, device approval, \
or two-factor authentication.

Important scope restriction:
- Only treat the email as relevant if it is clearly an authentication or account \
access message.
- If the email is NOT about login, sign-in, registration, signup, account \
verification, or security confirmation, you MUST output exactly: NO_2FA_FOUND
- Ignore unrelated emails even if they contain numbers, links, or buttons.

Examples that MUST return NO_2FA_FOUND:
- newsletters, promotions, invoices, receipts, shipping updates
- password reset emails
- magic links or codes for marketing, unsubscribe, download, support, booking, \
order tracking, or general account notifications
- invitation emails unrelated to authentication or account verification
- any email where the link/code is not explicitly for login, signup, or verifying \
account access

Rules:
1. If the email is NOT an authentication/account-access email, output exactly: \
NO_2FA_FOUND
2. If the email is an authentication/account-access email but contains neither a \
usable login/signup verification code nor a confirmation link, output exactly: \
NO_2FA_FOUND
3. Only when the email is clearly for login, registration, signup, or account \
verification should you output a single JSON object with these keys:
   - "summary": a short one-sentence summary describing the sender and auth purpose \
(e.g. "GitHub login verification code").
   - "code": the 2FA / OTP / verification code as a string, or "" if none.
   - "link": the confirmation or verification URL as a string, or "" if none.
   - "link_label": a short 2-4 word button label describing what opening the link \
will do (e.g. "Approve login", "Verify email", "Confirm device", "Complete signup"), \
or "" if there is no relevant auth link.
4. Do NOT extract promo codes, order numbers, ticket numbers, reference IDs, or \
links unrelated to authentication.
5. If "link" is non-empty, "link_label" must also be non-empty, specific, and \
not generic. Never use labels like "Verify / Confirm".
6. Output ONLY the JSON object or the exact string NO_2FA_FOUND. Do NOT include \
any other text, explanation, or markdown formatting.\
"""


def _parse_response(text: str) -> dict | None:
    """Parse the LLM response into a result dict or None."""
    stripped = text.strip()

    if "NO_2FA_FOUND" in stripped:
        return None

    # Strip markdown code fences if present
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", stripped)
    if match:
        stripped = match.group(1).strip()

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        logger.error("Failed to parse LLM response as JSON: %s", stripped)
        return None

    if not isinstance(data, dict):
        logger.error("LLM response is not a JSON object: %s", stripped)
        return None

    summary = str(data.get("summary", "")).strip()
    code = str(data.get("code", "")).strip()
    link = str(data.get("link", "")).strip()
    link_label = " ".join(str(data.get("link_label", "")).split()).strip()

    if not code and not link:
        return None

    return {
        "summary": summary,
        "code": code,
        "link": link,
        "link_label": link_label,
    }


async def extract_2fa_from_email(subject: str, body: str) -> dict | None:
    """Send the email to OpenRouter and extract 2FA information.

    Returns a dict with keys ``summary``, ``code``, ``link``, and
    ``link_label`` when a 2FA code or confirmation link is found, or
    ``None`` otherwise.
    """
    user_message = f"Subject: {subject}\n\nBody:\n{body}"

    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    }

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                OPENROUTER_URL, json=payload, headers=headers
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(
            "OpenRouter API returned status %s: %s",
            exc.response.status_code,
            exc.response.text,
        )
        return None
    except httpx.TimeoutException:
        logger.error("OpenRouter API request timed out after 30 seconds")
        return None
    except httpx.HTTPError as exc:
        logger.error("HTTP error communicating with OpenRouter: %s", exc)
        return None

    try:
        result = response.json()
        content = result["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        logger.error(
            "Unexpected OpenRouter response structure: %s — raw body: %s",
            exc,
            response.text,
        )
        return None

    return _parse_response(content)
