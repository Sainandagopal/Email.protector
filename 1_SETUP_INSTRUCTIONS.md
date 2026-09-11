# Gmail Sender-IP Extractor — Setup Guide

## Step 1: Enable Gmail API & get credentials

1. Go to https://console.cloud.google.com/
2. Create a new project (or select an existing one)
3. In the left menu: **APIs & Services → Library** → search "Gmail API" → **Enable**
4. Go to **APIs & Services → Credentials**
5. Click **Create Credentials → OAuth client ID**
   - If prompted, configure the consent screen first (choose "Internal" if it's a Google Workspace account, "External" otherwise, add your email as a test user)
   - Application type: **Desktop app**
   - Name it anything (e.g. "ip-extractor")
6. Click **Create** → **Download JSON**
7. Rename the downloaded file to `credentials.json` (or `Credentials.json`) and place it in the same folder as `gmail_ip_extractor.py`

## Step 2: Install dependencies

```bash
backend\.venv\Scripts\pip.exe install google-auth-oauthlib google-api-python-client
```
*(or `pip install google-auth-oauthlib google-api-python-client` if using system Python)*

## Step 3: Run it

```bash
backend\.venv\Scripts\python.exe gmail_ip_extractor.py
```
*(or `python gmail_ip_extractor.py` if python is in PATH)*

- First run opens a browser window asking you to log in and approve access — this creates a `token.json` so you won't have to log in again.
- The script will then poll your inbox every 60 seconds and print the sender IP for each new email.

## Step 4 (optional): Run continuously in the background

**Linux/Mac:**
```bash
nohup python gmail_ip_extractor.py > ip_log.txt 2>&1 &
```

**Windows (PowerShell background job):**
```powershell
Start-Process -FilePath "backend\.venv\Scripts\python.exe" -ArgumentList "gmail_ip_extractor.py" -WindowStyle Hidden
```

## Important notes

- **Read-only scope is used** (`gmail.readonly`) — the script cannot send, delete, or modify your mail.
- If the sender used Gmail/Outlook/Yahoo webmail, the IP you get back is usually the **webmail provider's server IP**, not the sender's personal device — this is normal and expected, not a bug in the script.
- `token.json` contains your access token — keep it private, don't commit it to git.
- Google's OAuth consent screen may show an "unverified app" warning since this is your own personal script — click **Advanced → Go to (your app name) [unsafe]** to proceed. This is normal for personal/internal-use apps.

## Next step: real-time instead of polling

The attached script polls every 60 seconds. If you want instant push notifications instead (via Google Cloud Pub/Sub), let me know and I'll provide that version — it requires a bit more GCP setup (a Pub/Sub topic + a public webhook endpoint to receive pushes).
