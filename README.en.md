# 📬 Email Manager

![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688)
![100% local](https://img.shields.io/badge/100%25-local%20%26%20private-success)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

[Français](README.md) · **English**

> A **local** dashboard to analyze, clean up and secure your mailboxes —
> newsletter detection, bulk unsubscribe, brand-impersonation phishing
> detection, and automatic sorting.

Email Manager connects to your mailboxes over **IMAP** (Outlook via OAuth,
Gmail, Yahoo, iCloud, Free…), analyzes message **headers without sending
anything outside**, and gives you a dashboard to take back control: who spams
you, who impersonates a brand, who's dormant, and how to clean up in a few clicks.

🔒 **100% local & private.** No data ever leaves your machine. Accounts,
credentials and the message cache stay in the `data/` folder, which is excluded
from the git repository.

---

## 🖼 Preview

![Demo](docs/demo.gif)

| Senders | Phishing detection | Insights |
|---|---|---|
| ![Senders](docs/screenshots/01-expediteurs.png) | ![Suspects](docs/screenshots/02-suspects.png) | ![Insights](docs/screenshots/03-insights.png) |

> Screenshots use **demo data**; addresses are additionally blurred. No real
> data is shown.

---

## ✨ Features

- **Multi-account** — Outlook/Hotmail (OAuth2), Gmail, Yahoo, iCloud, Free,
  Orange… (any IMAP provider). IMAP server auto-detected from the domain.
- **Multi-folder scan** — inbox, Spam, Archives… with **speed modes**:
  *new mail* (incremental, near-instant), *3 months*, *1 year* or *full*.
  **Parallelized** fetching (several IMAP connections).
- **Promo / newsletter detection** via the `List-Unsubscribe` header, plus
  flagging of **unread** mail (the best signal for senders to clean up).
- **🛡 Anti-phishing / brand impersonation** — spots look-alike domains
  (`paypal-secure.com`), brands used as a subdomain of an unrelated domain, and
  brand display names sent from a personal address or failing DMARC. Uses
  **whole-word** matching to minimize false positives.
- **Automatic categorization**: Promo, Social, Finance, Notifications, Contacts,
  Suspicious.
- **Unsubscribe** — single or **bulk**: HTTP one-click (RFC 8058) with fallback
  to email-based unsubscribe (`mailto:` over SMTP).
- **Bulk actions**: delete (trash), archive, move — by sender, across all
  accounts at once.
- **Automatic rules** + **protected senders** + **scheduled scan**.
- **Insights**: monthly volume, biggest space hogs, dormant senders.
- **Export** to Excel / CSV.

---

## 🗂 Project structure

```
email-manager/
├── backend/                 # FastAPI API + IMAP/SMTP/OAuth logic
│   ├── main.py              # API routes, scan orchestration
│   ├── imap_client.py       # IMAP connection, parallel scan, actions
│   ├── oauth_ms.py          # Microsoft OAuth2 (device-code flow)
│   ├── smtp_client.py       # SMTP sending (mailto unsubscribe)
│   ├── phishing.py          # brand-impersonation detection
│   ├── categorize.py        # sender categorization
│   ├── rules.py             # sorting rules + protected senders
│   ├── scheduler.py         # scheduled automatic scan
│   ├── unsubscribe.py       # HTTP / mailto unsubscribe
│   └── db.py                # local storage (SQLite + keyring)
├── frontend/                # web UI (HTML/CSS/JS, no build step)
├── data/                    # local data (git-ignored)
├── requirements.txt
├── run.bat                  # Windows launcher
└── run.sh                   # Linux / macOS launcher
```

---

## 🚀 Install & run

**Requirements:** Python 3.10+.

```bash
# Windows
run.bat

# Linux / macOS
./run.sh
```

First run creates the virtual environment, installs dependencies, and starts the
server on **http://127.0.0.1:8000**.

---

## 🔑 Connecting accounts

### Outlook / Hotmail / Live — OAuth (required)

Microsoft disabled password-based IMAP on personal accounts, so sign-in uses
**OAuth** (browser authentication, no password stored). To avoid creating an
Azure app, the tool defaults to **Mozilla Thunderbird's public application ID**
(personal use). In **⚙ Accounts → Outlook tab**, enter your address, click
*Connect*, copy the displayed code on the Microsoft page and approve. You can
provide your own Azure `client_id` under "Advanced".

### Gmail / Yahoo / iCloud / others — app password

These providers require an **app password** (after enabling two-factor auth):
Gmail (Google Account → Security → App passwords, IMAP enabled), Yahoo, iCloud
(appleid.apple.com), Free/Orange (member area).

---

## 🧭 Usage

1. **⚙ Accounts** → add your addresses.
2. Pick a **scan mode** (start with *3 months* for a quick result) then
   **⟳ Scan**. After a first scan, *new mail* only reads recent messages.
3. Explore the four views: **Senders**, **Suspicious** (phishing), **Insights**,
   **Rules & automation**.

> ⚠️ **Delete**, **Archive** and **Unsubscribe all** really modify your
> mailboxes. Add your contacts and bank to **protected senders** before any
> bulk cleanup.

---

## 🔐 Security & privacy

- **Everything is local**: runs on `127.0.0.1`; no data sent to any third party
  (besides the direct connection to your mail provider).
- **Credentials** are stored in the OS credential manager (Windows Credential
  Manager / Keychain) when available, otherwise locally in `data/accounts.json`.
- The **`data/` folder is git-ignored**: accounts, tokens and the message cache
  are never versioned or shared.
- Only message **headers** are read (sender, subject, date, `List-Unsubscribe`,
  `Authentication-Results`), never the email body.

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 🛠 Tech stack

- **Backend**: Python, FastAPI, Uvicorn, IMAPClient, keyring, openpyxl.
- **Frontend**: vanilla HTML / CSS / JavaScript (no build step).
- **Storage**: SQLite (cache) + JSON (config) + keyring (secrets).

## ⚖️ Disclaimer

Provided "as is", for personal use. Bulk delete and unsubscribe operations are
powerful: double-check your filters and use the protected-senders list. The
authors accept no liability for any loss of mail.

## 📄 License

[MIT](LICENSE).
