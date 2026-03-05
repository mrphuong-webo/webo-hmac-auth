# WEBO HMAC Auth - Hướng dẫn Postman + n8n + ChatGPT

Tài liệu này giúp bạn:
- Test MCP endpoint bằng Postman.
- Kết nối n8n gọi MCP qua HTTP Request.
- Tạo prompt chuẩn để ChatGPT hướng dẫn agent/tool đúng format.

---

## 1) Chuẩn bị thông tin

Bạn cần các giá trị sau:
- `BASE_URL`: ví dụ `https://w88.icu`
- `MCP_PATH`: `/wp-json/mcp/v1/router`
- `KEY_ID`: dạng `wk_xxx`
- `SECRET`: secret chỉ hiển thị 1 lần khi tạo/rotate key

Từ đó có:
- `URL = BASE_URL + MCP_PATH`

Lưu ý bảo mật:
- Không commit `SECRET` vào git.
- Không chụp màn hình lộ `SECRET`.
- Nên rotate key nếu nghi ngờ lộ.

---

## 2) Postman setup (khuyến nghị dùng Pre-request Script)

### 2.1 Tạo Collection Variables

Trong Postman Collection, tạo variables:
- `base_url` = `https://w88.icu`
- `mcp_path` = `/wp-json/mcp/v1/router`
- `url` = `{{base_url}}{{mcp_path}}`
- `key_id` = `wk_xxx`
- `secret` = `<one-time-secret>`
- `session_id` = `` (để trống ban đầu)

### 2.2 Request chuẩn

- Method: `POST`
- URL: `{{url}}`
- Header:
  - `Content-Type: application/json`
  - `X-WEBO-KEY: {{key_id}}`
  - `X-WEBO-TS: {{ts}}`
  - `X-WEBO-SIGN: {{sign}}`

Body để test `tools/list`:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 2
}
```

### 2.3 Pre-request Script (copy/paste)

```javascript
const method = pm.request.method;
const path = pm.collectionVariables.get('mcp_path');
const secret = pm.collectionVariables.get('secret');

const ts = Math.floor(Date.now() / 1000).toString();
pm.variables.set('ts', ts);

let rawBody = pm.request.body && pm.request.body.raw ? pm.request.body.raw : '';

const bodyHash = CryptoJS.SHA256(CryptoJS.enc.Utf8.parse(rawBody)).toString(CryptoJS.enc.Hex);
const baseString = `${method}\n${path}\n${ts}\n${bodyHash}`;

const sign = CryptoJS.HmacSHA256(baseString, secret);
const signBase64 = CryptoJS.enc.Base64.stringify(sign);
pm.variables.set('sign', signBase64);
```

### 2.4 Initialize trước khi tools/call

Body `initialize`:

```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": { "name": "postman", "version": "1.0" }
  },
  "id": 1
}
```

Tests tab (lưu `session_id`):

```javascript
const json = pm.response.json();
if (json && json.result && json.result.session_id) {
  pm.collectionVariables.set('session_id', json.result.session_id);
}
```

### 2.5 tools/call mẫu

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "session_id": "{{session_id}}",
    "name": "webo/list-posts",
    "arguments": { "per_page": 5 }
  },
  "id": 3
}
```

---

## 3) n8n setup (không cần package MCP riêng)

Bạn có thể dùng node `HTTP Request` để gọi trực tiếp MCP router.

### 3.1 Biến dùng chung (Set node hoặc Credentials)

- `base_url`
- `mcp_path`
- `key_id`
- `secret`
- `session_id` (lấy sau initialize)

### 3.2 Flow tối thiểu

1. `Set` (chuẩn bị body JSON-RPC)
2. `Code` (tính `ts` + `sign`)
3. `HTTP Request` (gọi MCP)
4. `IF` (check lỗi)
5. `Set`/`Merge` (lưu `session_id`)

### 3.3 Code node tính chữ ký (JavaScript)

```javascript
const crypto = require('crypto');

const method = 'POST';
const path = $json.mcp_path;
const ts = Math.floor(Date.now() / 1000).toString();

const bodyObj = $json.body; // object JSON-RPC
const bodyRaw = JSON.stringify(bodyObj);

const bodyHash = crypto.createHash('sha256').update(bodyRaw, 'utf8').digest('hex');
const baseString = `${method}\n${path}\n${ts}\n${bodyHash}`;
const sign = crypto.createHmac('sha256', $json.secret).update(baseString, 'utf8').digest('base64');

return [{
  ...$json,
  ts,
  sign,
  bodyRaw,
}];
```

### 3.4 HTTP Request node

- Method: `POST`
- URL: `{{$json.base_url + $json.mcp_path}}`
- Send Body: `Raw` (JSON) với value: `{{$json.bodyRaw}}`
- Headers:
  - `Content-Type: application/json`
  - `X-WEBO-KEY: {{$json.key_id}}`
  - `X-WEBO-TS: {{$json.ts}}`
  - `X-WEBO-SIGN: {{$json.sign}}`

### 3.5 Trình tự gọi khuyến nghị

- Bước 1: `initialize` -> lưu `session_id`
- Bước 2: `tools/list`
- Bước 3: `tools/call` với `session_id`

---

## 4) Prompt mẫu đưa cho ChatGPT

Bạn có thể copy prompt sau để ChatGPT sinh request đúng format:

```text
Bạn là trợ lý kỹ thuật tích hợp MCP qua HMAC.
Hãy trả về JSON-RPC body hợp lệ cho endpoint /wp-json/mcp/v1/router.
Yêu cầu bắt buộc:
1) Luôn đi theo flow: initialize -> tools/list -> tools/call.
2) Khi tạo tools/call phải có params.session_id, params.name, params.arguments.
3) Không bịa tool name; chỉ dùng tool có trong tools/list.
4) Nếu tool thiếu tham số required, hãy báo thiếu gì trước khi gọi.
5) Trả output theo 2 phần:
   - "request_body": JSON để gửi
   - "explain": giải thích ngắn vì sao body đúng
Ngữ cảnh site:
- base_url: <YOUR_BASE_URL>
- mcp_path: /wp-json/mcp/v1/router
- auth: X-WEBO-KEY / X-WEBO-TS / X-WEBO-SIGN (ký ở client)
```

Prompt nâng cao cho n8n agent:

```text
Hãy đóng vai n8n workflow architect.
Thiết kế flow gọi WEBO MCP bằng HTTP Request + HMAC signature.
Đầu ra cần có:
1) Danh sách node theo thứ tự.
2) Input/Output chính của từng node.
3) Đoạn JavaScript code node để tính SHA256(body) và HMAC base64.
4) Cách lưu và tái sử dụng session_id.
5) Cách retry khi HTTP 401/403/429.
Giữ thiết kế tối giản, production-safe, không dùng package ngoài.
```

---

## 5) Lỗi thường gặp và cách xử lý nhanh

- `401 Unauthorized`
  - Sai `KEY_ID`, sai `SECRET`, hoặc clock lệch nhiều.
- `Invalid signature`
  - Sai `PATH` trong base string (phải đúng `/wp-json/mcp/v1/router`).
  - Hash body không khớp raw JSON thực gửi.
- `Invalid or missing session`
  - Chưa `initialize`, hoặc quên truyền `params.session_id`.
- `Missing required argument: ...`
  - Tool cần tham số bắt buộc trong `params.arguments`.
- `403 not in allowlist / denied`
  - Key bị giới hạn `allowlist/denylist` hoặc site scope.

---

## 6) Checklist trước khi go-live

- Đã test đủ 3 method: `initialize`, `tools/list`, `tools/call`.
- Đã lưu secret ở nơi an toàn (không để plain text trong workflow export).
- Đã cấu hình key scope tối thiểu cần dùng.
- Đã bật logging/monitoring cho lỗi 401/403/5xx.
- Đã có quy trình rotate key định kỳ.
