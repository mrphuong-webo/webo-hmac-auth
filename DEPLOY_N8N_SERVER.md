# Deploy n8n custom nodes lên server (192.168.200.15)

## Cấu trúc đã kiểm tra trên server

- **Host:** `root@192.168.200.15`
- **SSH key:** `O:\Lamviec\sshkey\test`

### Trên host `/opt/n8n/`

| Thư mục / file        | Ghi chú |
|-----------------------|--------|
| `docker-compose.yml`  | Stack n8n (traefik, redis, n8n). Container n8n **không** mount thư mục host. |
| `.env`                | Biến môi trường (SUBDOMAIN, DOMAIN_NAME, SSL_EMAIL, ...). |
| `custom/`             | **Rỗng** trên host, không dùng. |
| `n8n-nodes-webo-mcp/` | Mã nguồn node (build tại đây hoặc copy từ máy bạn). |
| `n8n-nodes-webo-mcp-pro/` | Mã nguồn node pro. |

### Trong container n8n (`n8n_n8n_1`)

- **Volume:** `n8n_data` → `/home/node/.n8n`
- **Custom nodes:** nằm trong volume tại **`/home/node/.n8n/custom/`**
  - `package.json` phụ thuộc:
    - `n8n-nodes-perfexcrm`
    - `n8n-nodes-webo-mcp` → `file:n8n-nodes-webo-mcp.tgz`
    - `n8n-nodes-webo-mcp-pro` → `file:n8n-nodes-webo-mcp-pro.tgz`
  - Các file `.tgz` phải đặt **cùng thư mục** với `package.json` (tức trong `custom/` trong container).

**Kết luận:** Thư mục **chính xác** để n8n load custom nodes là **trong container**: `/home/node/.n8n/custom/`. Trên host không có mount tương ứng; cập nhật node phải qua **copy file vào container** rồi `npm install` trong container.

---

## Quy trình deploy `n8n-nodes-webo-mcp` (hoặc pro)

### 1. Trên máy bạn (trong repo node)

```powershell
cd path\to\n8n-nodes-webo-mcp
npm run build
npm pack
# → tạo ra n8n-nodes-webo-mcp-0.1.0.tgz (version lấy từ package.json)
```

### 2. Copy tgz lên server

```powershell
$key = "O:\Lamviec\sshkey\test"
$server = "root@192.168.200.15"
$tgz = (Get-ChildItem -Filter "n8n-nodes-webo-mcp-*.tgz")[0].Name
scp -i $key $tgz ${server}:/tmp/
```

### 3. Trên server: đưa tgz vào container và cập nhật

Container cần file tên đúng `n8n-nodes-webo-mcp.tgz` trong `/home/node/.n8n/custom/` (vì `package.json` tham chiếu `file:n8n-nodes-webo-mcp.tgz`).

```bash
# Copy tgz vào thư mục custom trong container
docker cp /tmp/n8n-nodes-webo-mcp-0.1.0.tgz n8n_n8n_1:/home/node/.n8n/custom/n8n-nodes-webo-mcp.tgz

# Trong container: cài lại từ file local
docker exec n8n_n8n_1 sh -c "cd /home/node/.n8n/custom && npm install"

# Restart n8n để load node mới
cd /opt/n8n && docker compose -f docker-compose.yml restart n8n
```

### 4. (Tùy chọn) Build và pack trực tiếp trên server

Nếu bạn đã clone repo vào `/opt/n8n/n8n-nodes-webo-mcp`:

```bash
cd /opt/n8n/n8n-nodes-webo-mcp
npm ci
npm run build
npm pack
docker cp n8n-nodes-webo-mcp-*.tgz n8n_n8n_1:/home/node/.n8n/custom/n8n-nodes-webo-mcp.tgz
docker exec n8n_n8n_1 sh -c "cd /home/node/.n8n/custom && npm install"
cd /opt/n8n && docker compose -f docker-compose.yml restart n8n
```

---

## Biến môi trường gợi ý cho script deploy (PowerShell)

- `N8N_SSH_KEY` = `O:\Lamviec\sshkey\test`
- `N8N_SERVER` = `192.168.200.15`
- `N8N_REMOTE_PATH` = `/opt/n8n` (để chạy docker compose trên server)
- Container name: `n8n_n8n_1`, custom path trong container: `/home/node/.n8n/custom/`
