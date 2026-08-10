// Package blob LocalProvider 的「存储后端」端点。
//
// # 为什么需要它
//
// CS 模式下客户端直传的目标是 cs.101.com；本地开发没有那台服务器，
// 所以由本服务提供一个**独立于元数据 API** 的 /blob 端点充当存储后端。
//
// 架构上它与 /api/v1/files 是两回事：
//   - /api/v1/files  元数据 API，JWT 认证，只处理 JSON，不碰字节
//   - /blob          存储后端，HMAC 签名 URL 自鉴权，只搬字节，不碰 DB
//
// 客户端流程与 CS 模式完全同构：presign 拿 URL → 直传该 URL → 回调注册。
// 切到 provider=cs 后 /blob 自动不注册，客户端代码一行不用改。
package blob

import (
	"github.com/gin-gonic/gin"
	"whitestone.top/prism-fusion/global"
	"whitestone.top/prism-fusion/plugin"

	"nucleagent-storage/internal/config"
	"nucleagent-storage/provider"
)

// BlobPlugin 本地 blob 直传/直取插件。
type BlobPlugin struct {
	plugin.BasePlugin
	handler gin.HandlerFunc
}

var defaultPlugin = &BlobPlugin{
	BasePlugin: plugin.BasePlugin{
		PluginName:        "blob",
		PluginDescription: "本地存储后端 - 签名 URL 直传/直取（provider=local 时启用）",
	},
}

func init() {
	plugin.Register(defaultPlugin)
}

// Init 在 provider=local 时装配 blob handler。
// 其它 provider 下不装配，/blob 端点不存在。
func Init(cfg *config.Config, prv provider.Provider) {
	lp, ok := prv.(*provider.LocalProvider)
	if !ok {
		return
	}
	defaultPlugin.handler = newHandler(lp, cfg.MaxSize)
	global.PRISM_LOG.Info("Storage blob endpoint enabled at " + provider.BlobPath)
}

// Priority blob 需在 auth 之前拿到请求。
//
// 实际上 JWT 中间件只拦 /api/ 前缀，/blob 天然放行；
// 这里仍设小优先级，确保签名校验先于其它业务中间件执行。
func (p *BlobPlugin) Priority() int { return 5 }

// GlobalMiddlewares 以全局中间件形式挂载 /blob 处理器。
//
// 用全局中间件而非 huma 路由：blob 收发的是任意二进制流，
// 不该进 OpenAPI 文档，也不该被 huma 的 JSON 序列化链路碰。
func (p *BlobPlugin) GlobalMiddlewares() []gin.HandlerFunc {
	if p.handler == nil {
		return nil
	}
	return []gin.HandlerFunc{p.handler}
}
