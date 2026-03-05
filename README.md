# WEBO HMAC Auth

HMAC authentication layer for:
- `/wp-json/mcp/*` (khuyến nghị: `/wp-json/mcp/v1/router`)
- `/wp-json/wp-abilities/*`

## Dependency
- Plugin này hoạt động cùng `webo-wordpress-mcp` (core MCP gateway).

## Network activation (multisite)
1. Upload plugin folder to `wp-content/plugins/webo-hmac-auth`.
2. Go to **Network Admin → Plugins**.
3. Click **Network Activate** for **WEBO HMAC Auth**.
4. Manage per-user keys directly at **Network Admin → Users → Edit User** (`/wp-admin/network/user-edit.php?user_id={id}`).

## Permission model
- Key execution runtime maps to `wp_user_id`, so tool permissions follow the user's role/capabilities on the current site.
- Network admin (`manage_network_options`) can create/revoke/rotate all keys at **Network Admin → Users → Edit User**.

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
URL="https://w88.icu/wp-json/mcp/v1/router"
METHOD="POST"
PATH="/wp-json/mcp/v1/router"
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

> Legacy endpoint `/wp-json/mcp/mcp-adapter-default-server` vẫn được hỗ trợ nếu môi trường cũ đang dùng.
