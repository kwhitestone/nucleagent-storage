package file

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gin-gonic/gin"
	"github.com/kwhitestone/prism-fusion/global"
	"github.com/kwhitestone/prism-fusion/plugin"

	"github.com/kwhitestone/nucleagent-storage/addons/file/router"
	"github.com/kwhitestone/nucleagent-storage/addons/file/svc"
	"github.com/kwhitestone/nucleagent-storage/internal/config"
	"github.com/kwhitestone/nucleagent-storage/provider"
)

// FilePlugin 文件元数据插件。
type FilePlugin struct {
	plugin.BasePlugin
	svc *svc.Service
}

// defaultPlugin 全局单例，供 main 注入配置与 Provider。
var defaultPlugin = &FilePlugin{
	BasePlugin: plugin.BasePlugin{
		PluginName:        "file",
		PluginDescription: "文件元数据 - presign 上传/注册/查询/签名下载/删除（不代理字节流）",
	},
}

func init() {
	plugin.Register(defaultPlugin)
}

// Init 注入配置与存储后端。必须在 core.RunServer() 之前调用。
func Init(cfg *config.Config, prv provider.Provider) *svc.Service {
	s := svc.NewService(cfg, prv)
	defaultPlugin.svc = s
	return s
}

// RoutePrefix 元数据 API 都在 /api/v1 下（storage 是独立服务，不用 addons 前缀）。
func (p *FilePlugin) RoutePrefix() string { return "/api/v1" }

// RegisterRoutes 注册文件路由。
func (p *FilePlugin) RegisterRoutes(api huma.API) {
	if p.svc == nil {
		global.PRISM_LOG.Error("storage: file 插件未初始化（Init 未调用），跳过路由注册")
		return
	}
	router.RegisterRoutes(api, p.svc)
	global.PRISM_LOG.Info("Storage file plugin routes registered")
}

// Models 暴露 files 表供框架 AutoMigrate。
func (p *FilePlugin) Models() []interface{} {
	return []interface{}{&svc.File{}}
}

// Middlewares 作用域中间件：仅对 /api/v1 前缀生效。
func (p *FilePlugin) Middlewares() []gin.HandlerFunc {
	return []gin.HandlerFunc{BridgeMiddleware()}
}

// BridgeMiddleware 把 JWT 中间件写入 gin.Context 的 user_id 桥接到 request context，
// 供 huma handler 读取（与 core/auth 的 addons 同模式）。
//
// 同时把 S2S 调用方标识（X-Service-Name）带入 context，用于 created_by 审计。
func BridgeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		if v, ok := c.Get("user_id"); ok {
			uid, _ := v.(uint)
			ctx = context.WithValue(ctx, router.UserIDKey(), uid)
		}
		if svcName := c.GetHeader("X-Service-Name"); svcName != "" {
			ctx = context.WithValue(ctx, router.CallerKey(), "svc:"+svcName)
		}
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
