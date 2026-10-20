# Optional mailbox adapters

`mail_readers.py` can read raw MIME from Gmail or Microsoft Graph and run it through the same analysis as the desk. **The adapters are tested against injected provider responses only. They have not been run against a live Gmail or Graph account.**

## What they do and refuse to do

- GET requests only, to two fixed HTTPS hosts (`gmail.googleapis.com`, `graph.microsoft.com`). Redirects are refused. Responses are size-limited.
- No sending, marking read, moving, labelling, deleting or quarantine calls.
- The web UI never accepts tokens. The command line reads one from `MAIL_ACCESS_TOKEN`.
- `work/alerts.json` keeps at most 100 observations: a hashed message reference, timestamp, finding titles, score and model label. No subject, sender, body, token or attachment is stored. The file is written with owner-only permissions.

## Try it without an account

```sh
python mail_readers.py fixture --watch --once
```

Then open **Mailbox watch** and select **Refresh observations**. It shows two observations from shipped synthetic fixtures.

## Using your own test mailbox

- **Gmail:** an existing Google project with the Gmail API, a Desktop OAuth client and only the `gmail.readonly` scope. `gmail.metadata` cannot supply bodies.
- **Microsoft Graph:** an Entra public-client app with delegated `Mail.Read`. `Mail.ReadBasic` omits bodies.

This project does not create app registrations, run an OAuth flow, store refresh tokens or renew tokens. Get a token through the provider's own flow, then pass it without echo:

```sh
python - <<'PY'
import getpass, os, subprocess, sys
env = dict(os.environ, MAIL_ACCESS_TOKEN=getpass.getpass('Read-only access token: '))
subprocess.run([sys.executable, 'mail_readers.py', 'gmail', '--watch', '--once'], env=env, check=True)
PY
```

Change `gmail` to `graph` as needed. Omit `--once` to poll every 60 seconds (minimum 30, `--interval` to change).

## Limits

One page of up to 20 inbox messages per cycle, no pagination, no Gmail history or Graph delta cursors, no push notifications. Bursts can be missed. Restarting can repeat observations. Token expiry, throttling or network failure stop the command. This is not a mail-client plugin and does nothing before delivery.

API references used for the adapters are listed in [SOURCES.md](SOURCES.md).
