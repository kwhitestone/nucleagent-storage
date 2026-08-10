package router

import (
	"context"
	"strconv"
)

// ctxKey 是 request context 键类型（避免字符串键冲突）。
type ctxKey int

const (
	// userIDKey JWT 中间件解析出的用户 ID。
	userIDKey ctxKey = 1
	// callerKey S2S 调用方标识（服务名）。
	callerKey ctxKey = 2
)

// UserIDKey 返回 user_id 的 context key（供 BridgeMiddleware 写入）。
func UserIDKey() ctxKey { return userIDKey }

// CallerKey 返回 caller 的 context key（供 BridgeMiddleware 写入）。
func CallerKey() ctxKey { return callerKey }

// callerFromCtx 解析创建者标识：优先 JWT 用户 ID，其次 S2S 服务名。
//
// 用于 files.created_by 审计字段；两者都没有时返回空串（不阻断流程，
// 认证由 JWT 中间件统一把关，这里只做归属标注）。
func callerFromCtx(ctx context.Context) string {
	if uid, ok := ctx.Value(userIDKey).(uint); ok && uid != 0 {
		return "user:" + strconv.FormatUint(uint64(uid), 10)
	}
	if caller, ok := ctx.Value(callerKey).(string); ok && caller != "" {
		return caller
	}
	return ""
}
