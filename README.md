# CPM MCP Server

MCP server (Python) chia sẻ dữ liệu MySQL cho người/doanh nghiệp bên ngoài. Mỗi bên nhận một **token riêng**, token chỉ đọc được **những bảng bạn chọn lúc cấp**. Thu hồi hoặc đổi quyền có hiệu lực ngay.

```
Client (Claude, Cursor, app của doanh nghiệp)
   │  Authorization: Bearer cpm_xxx
   ▼
/mcp       → xác thực token → tool (list_tables, describe_table, query_table, count_rows) → MySQL (user chỉ-đọc)
/admin/v1  → X-Admin-Key + IP nội bộ → cấp / sửa / thu hồi token   (CRM backend gọi vào đây)
```

## Chạy nhanh

### Docker (khuyến nghị)

```powershell
copy .env.example .env      # rồi điền MYSQL_PASSWORD và ADMIN_API_KEYS
docker compose up -d --build
curl http://127.0.0.1:8000/healthz
```

Cổng được bind vào `127.0.0.1` có chủ đích. Muốn mở ra ngoài, đặt reverse proxy HTTPS phía trước (xem [Mở ra ngoài](#mở-ra-ngoài-internet)).

### Local (dev)

```powershell
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\python -m uvicorn cpm_server.main:create_app --factory --port 8000
.venv\Scripts\python -m pytest
```

### Chuẩn bị MySQL (làm một lần)

Server **không dùng root**. Tạo user chỉ-đọc:

```sql
CREATE USER 'cpm_reader'@'%' IDENTIFIED BY '<mật-khẩu>' WITH MAX_USER_CONNECTIONS 20;
GRANT SELECT ON forge.* TO 'cpm_reader'@'%';
```

Sinh admin key: `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

## Cấp token

Mở Swagger UI **`http://127.0.0.1:8000/admin/v1/docs`**, bấm *Authorize*, nhập `X-Admin-Key`, rồi dùng `POST /tokens`. Hoặc dùng curl:

```bash
KEY=<ADMIN_API_KEY>

# xem bảng nào cấp được
curl -H "X-Admin-Key: $KEY" http://127.0.0.1:8000/admin/v1/tables

# cấp token (secret chỉ hiện MỘT LẦN trong response)
curl -X POST http://127.0.0.1:8000/admin/v1/tokens \
  -H "X-Admin-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"name":"ACME báo cáo","organization_name":"ACME","organization_ref":"crm-42",
       "tables":["countries","cities"],"expires_at":"2027-01-01T00:00:00Z","created_by":"admin@cpm"}'

# đổi quyền (có hiệu lực ngay)
curl -X PATCH http://127.0.0.1:8000/admin/v1/tokens/<id> -H "X-Admin-Key: $KEY" \
  -H "Content-Type: application/json" -d '{"tables":["countries","cities","currencies"]}'

# thu hồi (401 ngay lập tức)
curl -X POST http://127.0.0.1:8000/admin/v1/tokens/<id>/revoke -H "X-Admin-Key: $KEY"

# lịch sử sử dụng
curl -H "X-Admin-Key: $KEY" http://127.0.0.1:8000/admin/v1/tokens/<id>/audit
```

## Người nhận kết nối thế nào

Đưa cho họ **URL MCP** và **token**.

Claude Code:

```bash
claude mcp add --transport http cpm-data https://mcp.example.com/mcp \
  --header "Authorization: Bearer cpm_xxxxxxxx_..."
```

Client khác hỗ trợ remote MCP kèm header:

```json
{
  "mcpServers": {
    "cpm-data": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer cpm_xxxxxxxx_..." }
    }
  }
}
```

Thử nhanh bằng MCP Inspector: `npx @modelcontextprotocol/inspector`, chọn *Streamable HTTP*, thêm header `Authorization`.

### Tool mà client thấy

| Tool | Chức năng |
|---|---|
| `list_tables` | Chỉ các bảng token được phép |
| `describe_table(table)` | Cột, kiểu, khoá chính |
| `query_table(table, columns?, filters?, order_by?, limit?, offset?)` | Đọc dữ liệu có lọc/sắp xếp/phân trang. `filters`: `[{column, op, value}]`, `op` ∈ `= != > >= < <= like in is_null` |
| `count_rows(table, filters?)` | Đếm có lọc |

Không nhận SQL thô. `limit` tối đa `MAX_ROWS` (mặc định 500), `has_more` cho biết còn trang kế.

## Cấu hình (`.env`)

| Biến | Ý nghĩa |
|---|---|
| `MYSQL_HOST/PORT/USER/PASSWORD/DATABASE` | Kết nối MySQL (user chỉ-đọc) |
| `TOKEN_DB_URL` | Nơi lưu token, grants, audit (SQLite, trên Docker volume `cpm_data`) |
| `ADMIN_ENABLED` | Tắt hẳn Admin API trên instance chỉ phục vụ MCP |
| `ADMIN_API_KEYS` | Danh sách key phân tách bằng dấu phẩy. Thêm key mới trước, đổi CRM sang key mới, rồi bỏ key cũ để xoay key không downtime |
| `ADMIN_ALLOWED_CIDRS` | Chỉ các mạng này gọi được `/admin/v1` (mặc định loopback + dải private) |
| `ADMIN_CORS_ORIGINS` | Để trống. Chỉ bật nếu frontend CRM gọi thẳng admin API |
| `ALLOWED_HOSTS` | Host header cho phép, ví dụ `mcp.example.com` |
| `GLOBAL_TABLE_DENYLIST` / `GLOBAL_COLUMN_DENYLIST` | Bảng/cột **không bao giờ** lộ ra, dù token có quyền (pattern `*`) |
| `MAX_ROWS`, `DEFAULT_LIMIT`, `QUERY_TIMEOUT_MS`, `MAX_RESPONSE_BYTES`, `MAX_CELL_CHARS` | Giới hạn truy vấn |

## Bảo mật

- Token lưu dạng **SHA-256 hash**, hiện plaintext đúng một lần khi tạo.
- Quyền được tra DB **ở mỗi request**: thu hồi, hết hạn hoặc đổi danh sách bảng có hiệu lực ngay.
- Tên bảng/cột chỉ được chấp nhận khi có trong schema thật; giá trị luôn là tham số bind. Bảng bị từ chối và bảng không tồn tại trả **cùng một thông báo** để không dò được tên bảng.
- MySQL: user `SELECT`-only, session `READ ONLY`, có `max_execution_time`.
- Mọi lệnh gọi (kể cả bị từ chối) được ghi audit.

### Cột và bảng nhạy cảm

Phân quyền chỉ theo **bảng**, nên cấp một bảng là lộ mọi cột của nó, trừ những cột nằm trong denylist. Mặc định đã chặn: `users.password`, `remember_token`, `pagination_token`, `booking_token`, `stripe_id`, `pm_last_four`, cùng các bảng `personal_access_tokens`, `password_resets`, `failed_jobs`, `jobs`, `migrations`, `telescope_*`, `pma__*`.

**Hãy tự rà trước khi cấp những bảng như `users`**: bảng này còn chứa dữ liệu cá nhân như `phone`, `dob`, `address`, `sexual_orientation`, `ip_address`, `latitude/longitude`. Nếu không muốn lộ, thêm vào `GLOBAL_COLUMN_DENYLIST`.

### Mở ra Internet

Chỉ expose `/mcp`. **Không bao giờ** proxy `/admin`. Ví dụ Caddy:

```
mcp.example.com {
    handle /mcp {
        reverse_proxy 127.0.0.1:8000
    }
    handle {
        respond 404
    }
}
```

Nginx: `location = /mcp { proxy_pass http://127.0.0.1:8000; proxy_buffering off; }` và `location / { return 404; }`.

Lưu ý: sau reverse proxy cùng máy, IP kết nối tới server là IP của proxy nên `ADMIN_ALLOWED_CIDRS` không còn phân biệt được người gọi. Quy tắc "chỉ forward `/mcp`" ở proxy mới là ranh giới thật.

## Tích hợp CRM (Settings → tạo token)

CRM **backend** gọi Admin API, trình duyệt không bao giờ cầm admin key.

```
Admin bấm "Tạo token" trong CRM Settings
  → CRM backend kiểm tra quyền admin của user
  → POST /admin/v1/tokens   (header X-Admin-Key)
  → CRM hiển thị secret MỘT LẦN để copy gửi doanh nghiệp
```

Spec đầy đủ (OpenAPI, dùng để sinh client): `GET /admin/v1/openapi.json`.

| Màn hình CRM | Endpoint |
|---|---|
| Danh sách bảng để tick chọn | `GET /admin/v1/tables` (`grantable=false` thì disable ô tick; `description` là nhãn thân thiện) |
| Đặt nhãn mô tả bảng | `PUT /admin/v1/tables/{name}/description` |
| Tạo token | `POST /admin/v1/tokens` `{name, organization_name, organization_ref?, tables[], expires_at?, created_by, note?}` |
| Danh sách token của một doanh nghiệp | `GET /admin/v1/tokens?organization_ref=...&status=active` |
| Sửa quyền / gia hạn | `PATCH /admin/v1/tokens/{id}` (`expires_at: null` để bỏ hạn) |
| Thu hồi | `POST /admin/v1/tokens/{id}/revoke` |
| Lịch sử dùng | `GET /admin/v1/tokens/{id}/audit` |

- `organization_ref` là ID doanh nghiệp bên CRM; `created_by` là admin CRM đang thao tác (lưu vào audit).
- Lỗi luôn có dạng `{"code","message","details"}`. Các `code` ổn định: `UNAUTHORIZED`, `FORBIDDEN_NETWORK`, `VALIDATION_ERROR`, `TABLE_NOT_FOUND`, `TABLE_NOT_GRANTABLE`, `INVALID_EXPIRY`, `TOKEN_NOT_FOUND`, `TOKEN_REVOKED`, `IDEMPOTENCY_KEY_REUSED`.
- Gửi header `Idempotency-Key` khi tạo token để retry an toàn. Replay trả về **cùng token nhưng không có secret** (secret không thể lấy lại); nếu CRM mất secret thì thu hồi và cấp token mới.

## Cấu trúc

```
src/cpm_server/
  main.py            ghép /mcp + /admin/v1 + /healthz
  config.py          cấu hình từ env
  security/          tokens (sinh/băm), middleware Bearer, authz theo bảng, denylist
  data/              kết nối MySQL + cache schema, query_builder an toàn
  mcp_tools/         4 tool MCP
  admin/             Admin API v1 (sub-app FastAPI riêng, có Swagger)
  store/             SQLite: tokens, grants, audit, mô tả bảng, idempotency
tests/               pytest (unit + qua HTTP với SQLite làm nguồn dữ liệu giả)
```
