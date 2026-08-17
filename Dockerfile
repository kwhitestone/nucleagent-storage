# syntax=docker/dockerfile:1
# =============================================================================
# nucleagent-storage 镜像：独立文件存储服务（presign 模式）。
#
# ⚠️ build context 必须是 workspace 根目录（Go replace 指向 ../../../../prism-fusion）：
#
#   docker build -t nucleagent-storage -f nucleagent-storage/Dockerfile .
#
# 两阶段：
#   1. go-build —— 构建 Go 二进制（含 replace 指向的本地 module）
#   2. final    —— distroless 风格的最小运行镜像
# =============================================================================

# ---- Stage 1: 构建 Go 二进制 ---------------------------------------------
FROM golang:1.25 AS go-build
ENV CGO_ENABLED=0 GO111MODULE=on GOPROXY=https://goproxy.cn,direct
WORKDIR /build

# Go module 根在 nucleagent-storage/app/src/server，replace 指向上层
COPY nucleagent-storage/app/src/server/ ./nucleagent-storage/app/src/server/
COPY prism-fusion/src/server/           ./prism-fusion/src/server/

WORKDIR /build/nucleagent-storage/app/src/server
RUN go build -ldflags="-s -w" -o /out/nucleagent-storage .

# ---- Stage 2: 运行镜像 ----------------------------------------------------
FROM alpine:3.20 AS final

# ca-certificates：provider=cs 时需要与 CS/CDN 建 HTTPS 连接
# tzdata：日志时间戳按本地时区
RUN apk add --no-cache ca-certificates tzdata wget && \
    adduser -D -u 10001 -h /opt storage

# 数据目录（provider=local 时的落盘位置，生产建议挂卷）
RUN mkdir -p /opt/data/uploads /opt/log && chown -R storage:storage /opt

# core.Viper() 从 CWD 读 config.yaml。
COPY --from=go-build /out/nucleagent-storage /usr/local/bin/nucleagent-storage
COPY nucleagent-storage/app/src/server/config.yaml /opt/config.yaml

WORKDIR /opt
USER storage

ENV STORAGE_LOCAL_DIR=/opt/data/uploads

EXPOSE 26610

# 健康检查打 storage 自己的 /api/v1/health（免认证）。
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:26610/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/nucleagent-storage"]
CMD []
