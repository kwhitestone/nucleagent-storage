// nucleagent-storage 独立文件存储服务（端口 26610）。
//
// 定位：轻量 presign 服务。管理文件元数据 + 签发上传/下载凭证，
// **不代理文件字节流** —— 客户端拿凭证直连存储后端（CS/CDN 或本地 blob 端点）。
package main

import (
	"fmt"

	"go.uber.org/zap"

	"whitestone.top/prism-fusion/core"
	"whitestone.top/prism-fusion/global"
	"whitestone.top/prism-fusion/initialize"

	// 框架内置 auth/rbac（storage 复用 JWT 认证，与 core 共享 signing-key）。
	_ "whitestone.top/prism-fusion/addons"
	// storage 业务插件：file（元数据）+ blob（本地存储后端）。
	_ "nucleagent-storage/addons"

	authMiddleware "whitestone.top/prism-fusion/addons/auth/middleware"

	"nucleagent-storage/addons/blob"
	"nucleagent-storage/addons/file"
	storageconfig "nucleagent-storage/internal/config"
	"nucleagent-storage/provider"
)

func main() {
	initializeSystem()
	core.RunServer()
}

func initializeSystem() {
	global.PRISM_VP = core.Viper()
	global.PRISM_LOG = core.Zap()
	zap.ReplaceGlobals(global.PRISM_LOG)

	// 加载 storage 业务配置（storage.* 段不在框架 config.Server 里）。
	cfg, err := storageconfig.Load()
	if err != nil {
		global.PRISM_LOG.Fatal("storage: 配置加载失败", zap.Error(err))
	}

	// 装配存储后端。
	prv, err := buildProvider(cfg)
	if err != nil {
		global.PRISM_LOG.Fatal("storage: 存储后端初始化失败", zap.Error(err))
	}

	// 注入到插件（必须在 RunServer 注册路由之前）。
	file.Init(cfg, prv)
	blob.Init(cfg, prv)

	// 健康检查免 JWT：框架的 JWT 中间件默认拦截所有 /api/ 前缀，
	// 而 /api/v1/health 要给容器 HEALTHCHECK / 负载均衡探活用，必须放行。
	authMiddleware.AddPublicPath("/api/v1/health")

	// 数据库：files 表由 file 插件的 Models() 提供，框架自动迁移。
	global.PRISM_DB = initialize.Gorm()
	if global.PRISM_DB == nil {
		global.PRISM_LOG.Fatal("storage: 数据库连接失败（storage 依赖 DB 存元数据）")
	}
	initialize.InitTables()

	global.PRISM_LOG.Info("nucleagent-storage initialized",
		zap.String("provider", prv.Name()),
		zap.Int64("maxSize", cfg.MaxSize),
		zap.Int("namespaces", len(cfg.Namespaces)),
	)
}

// buildProvider 按配置构造存储后端。
func buildProvider(cfg *storageconfig.Config) (provider.Provider, error) {
	switch cfg.Provider {
	case "cs":
		return provider.NewCSProvider(&cfg.CS), nil
	case "local":
		return provider.NewLocalProvider(&cfg.Local, cfg.SignSecret), nil
	default:
		return nil, fmt.Errorf("不支持的 provider: %s", cfg.Provider)
	}
}
