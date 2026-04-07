# Gmail-to-Telegram 2FA Relay Bot

Have you ever been absolutely crushed by the soul-draining burden of making *five whole clicks* just to open your email and copy a 2FA code? Fear no more, because this Python automation marvel is here to rescue you from that unspeakable hardship. It monitors multiple Gmail inboxes for two-factor authentication codes, login verifications, and confirmation links, then relays them straight to Telegram for instant access on your phone or desktop—so you can reclaim those precious, life-altering seconds.

## Features

- **Multi-account Gmail monitoring** — connect as many Gmail accounts as you need, managed entirely through Telegram commands
- **Real-time push notifications** — uses Google Cloud Pub/Sub for instant email detection (no polling)
- **LLM-powered extraction** — sends emails to an LLM via [OpenRouter](https://openrouter.ai) to intelligently extract 2FA codes and confirmation links
- **Instant Telegram delivery** — codes are sent as tap-to-copy inline buttons; verification links appear as clickable buttons, and when both are present they sit side-by-side
- **Per-account Telegram topics** — each connected Gmail account gets its own Telegram topic, keeping codes neatly separated by inbox
- **Dynamic account management** — add and remove Gmail accounts on the fly with `/add`, `/remove`, and `/list`; reconnecting an account reuses its existing topic
- **Configurable pre-filtering** — optionally skip emails that don't match 2FA-related keywords, saving LLM API costs
- **Optional email archiving** — automatically remove processed emails from your inbox after relaying
- **Docker-ready deployment** — ships with a `Dockerfile` and `docker-compose.yml` for one-command setup
- **Prebuilt GHCR image** — publishes a ready-to-run container image via GitHub Container Registry for easy upgrades and deployment
- **Automatic token refresh** — handles OAuth2 access-token renewal; disables accounts and alerts you if a refresh token is revoked

## Architecture

```
┌───────────┐   push    ┌──────────────┐  pull   ┌─────────────────┐
│   Gmail   │ ────────► │  Cloud       │ ──────► │   Bot Service   │
│  Inboxes  │  Pub/Sub  │  Pub/Sub     │         │  (main.py)      │
└───────────┘  notify   │  Topic/Sub   │         └────┬───────┬────┘
                        └──────────────┘              │       │
                                            fetch     │       │ extract
                                            email     │       │
                                                      ▼       ▼
                                               ┌──────────┐ ┌──────────┐
                                               │ Gmail API│ │ LLM via  │
                                               │          │ │OpenRouter│
                                               └──────────┘ └────┬─────┘
                                                                 │
                                                         send    │
                                                         message │
                                                                 ▼
                                                         ┌──────────────┐
                                                         │   Telegram   │
                                                         │     Chat     │
                                                         └──────────────┘
```

1. Gmail receives a new email and pushes a notification to a Cloud Pub/Sub topic.
2. The bot's Pub/Sub subscriber receives the notification containing the email address and a history ID.
3. The bot fetches new messages from the Gmail API using incremental history sync.
4. Each message is (optionally) pre-filtered for 2FA keywords, then sent to an LLM for extraction.
5. If a code or link is found, the bot sends a formatted message to your Telegram chat.
6. If archiving is enabled, the processed email is removed from the inbox.

## Prerequisites

| # | Requirement | Purpose |
|---|-------------|---------|
| 1 | **Python 3.11+** | Runtime (3.12 used in Docker image) |
| 2 | **Google Cloud Platform project** | Gmail API, Pub/Sub, OAuth2 |
| 3 | **Telegram Bot** | Delivery channel for 2FA messages |
| 4 | **OpenRouter API key** | LLM access for email parsing |
| 5 | **A public hostname or tunnel** | OAuth2 redirect callback |
| 6 | **Somewhere to host the bot** | Duh... VPS, homelab, or even a Raspberry Pi. |

## Setup Guide

### 1. Google Cloud Platform Setup

1. **Create a GCP project** at [console.cloud.google.com](https://console.cloud.google.com).

2. **Enable APIs** — go to *APIs & Services → Library* and enable:
   - Gmail API
   - Cloud Pub/Sub API

3. **Create OAuth 2.0 credentials**:
   - Go to *APIs & Services → Credentials → Create Credentials → OAuth client ID*.
   - Choose **Web application** as the application type.
   - Under *Authorized redirect URIs*, add:
     ```
     https://your-domain:8080/oauth/callback
     ```
     Replace `your-domain` with your actual hostname (must match `APP_HOSTNAME`).

4. **Create a Pub/Sub topic**:
   ```bash
   gcloud pubsub topics create gmail-notifications
   ```

5. **Create a Pull subscription** for the topic:
   ```bash
   gcloud pubsub subscriptions create gmail-notifications-sub \
     --topic=gmail-notifications
   ```

6. **Grant Gmail publish permissions** so that Gmail can push notifications to your topic:
   ```bash
   gcloud pubsub topics add-iam-policy-binding gmail-notifications \
     --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
     --role="roles/pubsub.publisher"
   ```

7. **Create a service account** for the bot with the **Pub/Sub Subscriber** role and download its JSON key:
   ```bash
   gcloud iam service-accounts create gmail-2fa-bot
   gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
     --member="serviceAccount:gmail-2fa-bot@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
     --role="roles/pubsub.subscriber"
   gcloud iam service-accounts keys create credentials.json \
     --iam-account=gmail-2fa-bot@YOUR_PROJECT_ID.iam.gserviceaccount.com
   ```

8. **Set the credentials environment variable** so the Google Cloud client library can authenticate:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
   ```
   When using Docker, mount the key file into the container and set the variable in your `.env`.

### 2. OAuth Consent Screen

1. Go to *APIs & Services → OAuth consent screen* in the GCP Console.
2. Choose **External** user type (or Internal if using Google Workspace).
3. Fill in the required app information fields.
4. Add the following scopes:
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/gmail.modify`
   - `https://mail.google.com/`
5. If the app is in **Testing** mode, add every Gmail address you plan to monitor under *Test users*.

### 3. Telegram Bot Setup

1. Open a chat with [@BotFather](https://t.me/BotFather) on Telegram.
2. Send `/newbot` and follow the prompts to create a bot.
3. Copy the **bot token** — you'll need it for `TELEGRAM_BOT_TOKEN`.
4. In **BotFather**, enable **forum topic mode** for the bot so it can create and use topics inside the private chat.
5. To find your **chat ID**, start a chat with [@userinfobot](https://t.me/userinfobot) and it will reply with your numeric chat ID. Use this for `ALLOWED_CHAT_ID`.

> It is recommended that you have a Telegram premium subscription because otherwise icons will get all messed up and the UX will be subpar. But it is not strictly required.

### 4. OpenRouter Setup

1. Sign up at [openrouter.ai](https://openrouter.ai).
2. Navigate to *Keys* and create a new API key.
3. Copy the key — you'll need it for `OPENROUTER_API_KEY`.
4. The default model is `google/gemini-2.0-flash-001`. You can change it via the `OPENROUTER_MODEL` variable to any model available on OpenRouter.

## Configuration

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
```

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather | — | Yes |
| `ALLOWED_CHAT_ID` | Numeric Telegram chat ID authorized to use the bot and host the per-account topics | — | Yes |
| `OPENROUTER_API_KEY` | API key from OpenRouter | — | Yes |
| `OPENROUTER_MODEL` | LLM model identifier on OpenRouter | `google/gemini-2.0-flash-001` | No |
| `GCP_PROJECT_ID` | Google Cloud project ID | — | Yes |
| `PUBSUB_TOPIC_NAME` | Pub/Sub topic name for Gmail notifications | `gmail-notifications` | Yes |
| `PUBSUB_SUBSCRIPTION_NAME` | Pub/Sub pull subscription name | `gmail-notifications-sub` | Yes |
| `GOOGLE_CLIENT_ID` | OAuth 2.0 client ID | — | Yes |
| `GOOGLE_CLIENT_SECRET` | OAuth 2.0 client secret | — | Yes |
| `APP_HOSTNAME` | Public base URL of the bot (e.g. `https://bot.yourdomain.com`) | — | Yes |
| `WEB_PORT` | Port for the OAuth callback web server | `8080` | No |
| `ENABLE_PRE_FILTER` | Skip emails that don't match 2FA keywords before calling the LLM | `false` | No |
| `ARCHIVE_PROCESSED_EMAILS` | Remove processed emails from the inbox after relaying | `false` | No |
| `DB_PATH` | Path to the SQLite database file | `/data/accounts.db` | No |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to the GCP service account JSON key file | — | Yes |

## Deployment

### Docker / Prebuilt Image (Recommended)

A prebuilt image is available on GitHub Container Registry (GHCR):

```bash
ghcr.io/mrfrederic/gmail-code-parser:latest
```

The included `docker-compose.yml` uses that image by default.

Then start the stack:

```bash
cp .env.example .env
# Edit .env with your values

# Mount your GCP service account key into the container
# by adding a volume in docker-compose.yml or setting the env var path accordingly

docker compose pull
docker compose up -d
```

If you prefer to build locally instead, uncomment the `build: .` line in `docker-compose.yml` and run:

```bash
docker compose up -d --build
```

The `docker-compose.yml` exposes the web server port and persists the SQLite database in a named volume (`bot_data` → `/data`).

### Manual

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your values

export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
python main.py
```

## Usage

Start a conversation with your bot on Telegram and use these commands:

| Command | Description |
|---------|-------------|
| `/start` | Show a welcome message and list available commands |
| `/add` | Generate an OAuth link to connect a new Gmail account |
| `/remove` | Show a list of connected accounts and remove one |
| `/list` | Display all currently monitored Gmail accounts |

### Connecting an Account

1. Send `/add` in the Telegram chat.
2. Click the **Login to Google** button the bot sends.
3. Sign in with the Gmail account you want to monitor and grant permissions.
4. You'll see a success page in the browser, and the bot sends a confirmation message in Telegram.
5. A dedicated Telegram topic named after that Gmail address is created (or reopened, if it existed before).
6. The account is now being monitored — any 2FA email will be relayed automatically into that topic.

## Message Format

When a 2FA email is detected, the bot posts it inside that account's dedicated Telegram topic. A typical message looks like:

> 📨 **From:** `noreply@github.com`
>
> GitHub login verification code
>
> `[ 849302 ]   [ Verify / Confirm ]`

- **The topic name identifies the Gmail account**, so the message body no longer repeats the receiving address.
- **Verification codes** appear as a tap-to-copy inline button labeled with the code itself (for example, `849302`).
- **Confirmation links** appear as a clickable inline button labeled **Verify / Confirm** that opens the URL directly.
- If an email contains both a code and a link, the two buttons are shown side-by-side in a single row.
- If an email contains only a code or only a link, only the relevant button is shown.
- Removing an account closes its topic; reconnecting the same address reopens and reuses it.

## Troubleshooting

Just ask ChatGPT or somthing, it is 2026.
If you found a bug or have a feature request, open an issue on GitHub.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

---

**MFCORP INDUSTRIAL SOLUTIONS** // 2026 ALL RIGHTS RESERVED