// nucleagent-storage 独立文件存储服务（默认端口 26610）。
//
// 定位：轻量 presign 服务。管理文件元数据 + 签发上传/下载凭证，
// **不代理文件字节流** —— 客户端拿凭证直连存储后端（本地 blob 端点或插件后端）。
//
// 存储后端通过 provider.Build 按配置装配；内置 local，其它后端见
// plugins/ 目录（git submodule，blank import 触发自注册）。
package main

import (

	"go.uber.org/zap"

	"github.com/kwhitestone/prism-fusion/core"
	"github.com/kwhitestone/prism-fusion/global"
	"github.com/kwhitestone/prism-fusion/initialize"

	// 框架内置 auth/rbac（storage 复用 JWT 认证，与 core 共享 signing-key）。
	_ "github.com/kwhitestone/prism-fusion/addons"
	// storage 业务插件：file（元数据）+ blob（本地存储后端）。
	_ "github.com/kwhitestone/nucleagent-storage/addons"
	// 存储后端插件（git submodule）。需要哪个后端就 import 哪个，
	// init() 里 RegisterFactory 自注册；不需要的后端零编译成本。

	authMiddleware "github.com/kwhitestone/prism-fusion/addons/auth/middleware"

	"github.com/kwhitestone/nucleagent-storage/addons/blob"
	"github.com/kwhitestone/nucleagent-storage/addons/file"
	storageconfig "github.com/kwhitestone/nucleagent-storage/internal/config"
	"github.com/spf13/viper"

	"github.com/kwhitestone/nucleagent-storage/provider"
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
	prv, err := buildProvider(cfg, global.PRISM_VP)
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
//
// local 直接注册（默认后端）；其它后端由插件 init() 自注册。
func buildProvider(cfg *storageconfig.Config, vp *viper.Viper) (provider.Provider, error) {
	provider.RegisterFactory("local", provider.NewLocalFactory(cfg.SignSecret))
	return provider.Build(cfg.Provider, vp)
}
