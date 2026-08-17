# nucleagent-storage

独立文件存储服务（端口 **26610**），为 core / executor / 未来其他服务提供文件存储能力。

> 开源版默认 **local 后端**（本地磁盘，开箱即用）；其它后端（如 CS）通过

## 核心设计：presign，不代理字节流

storage 是一个**轻量 presign 服务**，只做两件事：

1. 管理文件元数据（MySQL `files` 表）
2. 签发上传凭证 / 下载签名 URL

**它从不搬运文件字节。** 上传和下载都是客户端直连存储后端（CS/CDN 或本地 blob 端点），
服务端没有任何 `io.Copy` 中转。好处：storage 不会因大文件传输被打爆，水平扩容只受 DB 限制。

```
上传：客户端 ──presign──> storage        （拿凭证，JSON）
     客户端 ──直传────> CS / CDN        （字节流，不经 storage）
     客户端 ──注册────> storage        （回填元数据，JSON）

下载：客户端 ──签名────> storage        （拿签名 URL，JSON）
     客户端 ──直取────> CS / CDN        （字节流，不经 storage）
```

## API

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/upload/presign` | 生成上传凭证 |
| POST | `/api/v1/files` | 上传完成后注册元数据 |
| GET | `/api/v1/files/:id` | 获取文件元数据 |
| GET | `/api/v1/files/:id/download` | 生成签名下载 URL（`?redirect=true` 则 302） |
| DELETE | `/api/v1/files/:id` | 删除文件 |
| GET | `/api/v1/health` | 健康检查（免认证） |

除 health 外均需 `Authorization: Bearer <JWT>`（与 core/auth 共享 signing-key）
和 `X-Namespace: core|executor` 头。

交互式文档：<http://localhost:26610/scalar>

### 完整流程示例

```bash
TOKEN=$(curl -s -X POST http://localhost:26670/api/v1/addons/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | jq -r .data.accessToken)

# 1) 拿上传凭证
PRE=$(curl -s -X POST http://localhost:26610/api/v1/upload/presign \
  -H "Authorization: Bearer $TOKEN" -H 'X-Namespace: core' \
  -H 'Content-Type: application/json' \
  -d '{"filename":"a.txt","contentType":"text/plain","size":12}')

FILE_ID=$(echo $PRE | jq -r .data.fileId)
UP_URL=$(echo  $PRE | jq -r .data.uploadUrl)
STORED=$(echo  $PRE | jq -r .data.storedUrl)

# 2) 客户端直传（不经 storage 的元数据 API）
curl -X PUT "$UP_URL" -H 'Content-Type: text/plain' --data-binary @a.txt

# 3) 注册元数据
curl -X POST http://localhost:26610/api/v1/files \
  -H "Authorization: Bearer $TOKEN" -H 'X-Namespace: core' \
  -H 'Content-Type: application/json' \
  -d "{\"fileId\":\"$FILE_ID\",\"storedUrl\":\"$STORED\",\"size\":12,\"mimeType\":\"text/plain\"}"

# 4) 拿下载 URL，直连下载
DL=$(curl -s "http://localhost:26610/api/v1/files/$FILE_ID/download" \
  -H "Authorization: Bearer $TOKEN" -H 'X-Namespace: core' | jq -r .data.url)
curl -o out.txt "$DL"
```

**CS 私有文件（scope=0）的差异**：presign 阶段拿不到 `dentryId`，`storedUrl` 为空。
客户端需用 CS 上传响应里的 `dentry_id` 拼成 `cs-dentry://{dentryId}` 回传给第 3 步。

## Provider

| Provider | 上传目标 | 签名算法 | 用途 |
|----------|---------|---------|------|
| `local` | 本服务 `/blob` 端点（PUT） | HMAC-SHA256 | 开发环境 |
| `cs` | cs.101.com（POST multipart） | HMAC-SHA1 | 生产环境 |

CS 签名逻辑移植自 `agentia-engine/src/service/cs/cs_storage.go`，去掉了对 agentia
`config`/`global` 的依赖，自包含。等价性由 `provider/cs_test.go` 的交叉验证保证。

### `/blob` 是什么

CS 模式下客户端直传的目标是 cs.101.com；本地开发没有那台服务器，所以由本服务提供
一个**独立于元数据 API** 的 `/blob` 端点充当存储后端：

- `/api/v1/files` — 元数据 API，JWT 认证，只处理 JSON
- `/blob` — 存储后端，HMAC 签名 URL 自鉴权，只搬字节，不碰 DB

客户端流程与 CS 模式完全同构，切到 `provider=cs` 后 `/blob` 自动不注册，客户端代码一行不用改。

## 配置

见 `app/src/server/config.yaml`。关键项：

```yaml
storage:
  provider: local              # local(开发) / cs(生产)
  max-size: 104857600          # 单文件上限 100MB
  sign-secret: '${STORAGE_SIGN_SECRET}'   # LocalProvider URL 签名密钥
  cs:
    server-name: '${CS_SERVER_NAME}'
    access-key: '${CS_ACCESS_KEY}'
    secret-key: '${CS_SECRET_KEY}'
    scope: 1                   # 0=私有(签名下载) 1=公开
  local:
    dir: './data/uploads'
    base-url: 'http://localhost:26610'
  namespaces:                  # 命名空间白名单（隔离不同调用方）
    - {name: core,     prefix: /nucleagent/core/}
    - {name: executor, prefix: /nucleagent/executor/}
```

配置缺失即启动失败（fail fast），不静默降级。

## 隔离与安全

- **命名空间隔离**：`X-Namespace` 必须命中配置白名单；跨命名空间访问文件返回 403
- **对象路径**：用 `fileId` 而非原始文件名做主体（`{yyyy}/{mm}/{uuid}{ext}`），避免同名覆盖与文件名注入
- **签名绑定四要素**：method + path + expires + size，改任一项签名即失效
- **双重限额**：presign 声明的体积与全局 `max-size` 取小者，用 `io.LimitReader` 强制，不信任 `Content-Length`
- **路径穿越两道防线**：`SanitizeKey` 清洗 + `ResolvePath` 落盘前校验必须位于 `local.dir` 之内
  （即便签名被伪造也写不出去）
- **原子写入**：先写临时文件再 rename，失败不留半截文件
- **独立 CS 凭据**：与其他服务分开配置

## 开发

```bash
cd nucleagent-deploy
./scripts/dev.sh start storage      # 启动（依赖 infra 的 MySQL）
./scripts/dev.sh restart storage
./scripts/dev.sh stop storage
tail -f .dev-logs/storage.log
```

```bash
cd nucleagent-storage/app/src/server
go build ./... && go vet ./... && go test ./...
```

## 部署

```bash
# build context 必须是 workspace 根（Go replace 指向 prism-fusion）
docker build -t nucleagent-storage -f nucleagent-storage/Dockerfile .
```

生产环境记得：
- `STORAGE_PROVIDER=cs` + 配好 CS 凭据
- `STORAGE_SIGN_SECRET` 换成强随机值
- `provider=local` 时把 `/opt/data/uploads` 挂卷持久化

## 存储后端插件

除内置 `local` 外的存储后端以插件接入：主框架只认 `provider.Factory` 注册表
（`provider/registry.go`），插件包 init() 自注册，主框架零编译成本。

| 后端 | 仓库 | 接入方式 |
|------|------|----------|
| local（内置） | 本仓库 | `storage.provider: local` |

### 新增一个后端插件

1. 新建独立 Go module（module path 如 `github.com/kwhitestone/nucleagent-storage-xxx`）；
2. 实现主框架的 `provider.Provider` 接口，并在包 init() 调
   `provider.RegisterFactory("xxx", factory)`；
3. 配置段约定 `storage.xxx`，工厂收到该段的 viper 子树自行解析；
4. 以 submodule 挂到本仓库 `plugins/xxx`，主框架 main.go blank import
   `plugins/xxx`（或直接用插件自己的 module path import）。

### 本地多仓库联调


```
go 1.25
use (
    .
    ../../../../prism-fusion/src/server
)
```
