// Package addons 插件导入入口。
// 导入此包会触发所有业务插件的 init() 完成自动注册。
package addons

import (
	// 本地存储后端 - 签名 URL 直传/直取（provider=local 时启用）
	_ "nucleagent-storage/addons/blob"
	// 文件元数据 - presign/注册/查询/签名下载/删除
	_ "nucleagent-storage/addons/file"
)
