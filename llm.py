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
You are a strict 2FA extraction assistant. Your ONLY job is to analyze an email \
and determine whether it contains a two-factor authentication code or a \
confirmation/verification link.

Rules:
1. If the email does NOT contain any 2FA code and does NOT contain any \
confirmation or verification link, you MUST output exactly the string: \
NO_2FA_FOUND — nothing else.
2. If the email DOES contain a 2FA code and/or a confirmation/verification link, \
output a single JSON object with these keys:
   - "summary": a short one-sentence summary describing the sender and purpose \
(e.g. "GitHub login verification code").
   - "code": the 2FA / OTP / verification code as a string, or "" if none.
   - "link": the confirmation or verification URL as a string, or "" if none.
3. Output ONLY the JSON object or the string NO_2FA_FOUND. Do NOT include any \
other text, explanation, or markdown formatting.\
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

    if not code and not link:
        return None

    return {"summary": summary, "code": code, "link": link}


async def extract_2fa_from_email(subject: str, body: str) -> dict | None:
    """Send the email to OpenRouter and extract 2FA information.

    Returns a dict with keys ``summary``, ``code``, ``link`` when a 2FA code or
    confirmation link is found, or ``None`` otherwise.
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
