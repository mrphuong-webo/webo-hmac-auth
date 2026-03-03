# WEBO HMAC Auth

HMAC authentication layer for:
- `/wp-json/mcp/*`
- `/wp-json/wp-abilities/*`

## Network activation (multisite)
1. Upload plugin folder to `wp-content/plugins/webo-hmac-auth`.
2. Go to **Network Admin → Plugins**.
3. Click **Network Activate** for **WEBO HMAC Auth**.
4. Go to **Network Admin → WEBO API Keys** to create keys.

## Security model
- API key maps to a WordPress user (`wp_user_id`) (C1 model).
- Signature required via headers:
  - `X-WEBO-KEY`
  - `X-WEBO-TS`
  - `X-WEBO-SIGN`
- Secret is shown once at creation/rotation.
- Plain secret is not stored in plaintext DB columns.

## Signature base string

```text
METHOD + "\n" +
PATH + "\n" +
TS + "\n" +
SHA256(BODY_RAW)
```

## Example bash signing + curl

```bash
KEY_ID="wk_xxx"
SECRET="<one-time-secret>"
TS="$(date +%s)"
URL="https://w88.icu/wp-json/mcp/mcp-adapter-default-server"
METHOD="POST"
PATH="/wp-json/mcp/mcp-adapter-default-server"
BODY='{"jsonrpc":"2.0","method":"tools/list","id":1}'

BODY_HASH="$(printf '%s' "$BODY" | openssl dgst -sha256 -binary | xxd -p -c 256)"
BASE_STRING="${METHOD}\n${PATH}\n${TS}\n${BODY_HASH}"
SIGN="$(printf '%b' "$BASE_STRING" | openssl dgst -sha256 -hmac "$SECRET" -binary | openssl base64 -A)"

curl -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "X-WEBO-KEY: $KEY_ID" \
  -H "X-WEBO-TS: $TS" \
  -H "X-WEBO-SIGN: $SIGN" \
  -d "$BODY"
```
