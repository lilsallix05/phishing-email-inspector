# Source and API verification register

Checked on 19–20 October 2026. These are primary technical documentation references, not proof that an external integration was exercised. No source content or external dataset was used as a labeled email corpus.

| Primary reference | Implementation use / conclusion |
|---|---|
| [Python email parser](https://docs.python.org/3/library/email.parser.html) | `BytesParser(policy=policy.default)` parses MIME bytes and records defects; the explicit policy avoids relying on a future default. |
| [Gmail message get](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get) and [message resource](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages) | GET a message with `format=raw`; decode its `raw` field from base64url before MIME parsing. |
| [Gmail message list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list) | A bounded inbox ID listing uses `maxResults` and `labelIds=INBOX`. Pagination is a remaining requirement for complete mailbox coverage. |
| [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes) | `gmail.readonly` permits reading messages, is restricted, and requires appropriate consent. Metadata-only scope does not supply bodies. Broader write/send scopes are unnecessary. |
| [Google desktop OAuth](https://developers.google.com/identity/protocols/oauth2/native-app) | External operational setup uses a registered desktop client, PKCE, state and loopback redirect. Token acquisition is not implemented or run by this package. |
| [Microsoft Graph get message](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0) | `/me/messages/{id}/$value` retrieves MIME content with an Authorization bearer token. |
| [Microsoft Graph list messages](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0) | The adapter requests a bounded inbox page selecting IDs and sorting by received time. It does not follow continuation links. |
| [Microsoft Graph permission reference](https://learn.microsoft.com/en-us/graph/permissions-reference#mailread) | Delegated Mail.Read supplies message content; basic-mail permission excludes body/preview/attachments. No write/send permissions are needed. |
| [Microsoft device authorization flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code) | An externally authorized public client can obtain a user access token through device authorization; provider/tenant policy still applies. |

