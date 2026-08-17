// Package config storage 服务的业务配置加载。
//
// storage 复用 prism-fusion 的 core.Viper() 读取 config.yaml，
// 但 storage 业务段不在框架 config.Server 结构里，故此处用
// global.PRISM_VP 单独读取 storage.* 键（与 executor 的 internal/config 同模式）。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kwhitestone/prism-fusion/global"
)

// 默认值常量。
const (
	// DefaultMaxSize 单文件大小上限（100MB）。
	DefaultMaxSize int64 = 100 * 1024 * 1024
	// DefaultLocalDir LocalProvider 默认落盘目录。
	DefaultLocalDir = "./data/uploads"
	// DefaultExpires 签名有效期（秒）。
	DefaultExpires = 1800
)

// Local 对应 config.yaml 的 storage.local 段（开发环境用）。
type Local struct {
	Dir     string // 落盘根目录
	BaseURL string // 对外暴露的基础 URL（用于拼上传/下载地址）
	Expires int    // 上传/下载签名有效期（秒）
}

// GetExpires 返回本地签名有效期（秒）。
func (l *Local) GetExpires() int {
	if l.Expires <= 0 {
		return DefaultExpires
	}
	return l.Expires
}

// Namespace 命名空间：不同调用方（core/executor）的路径隔离单元。
type Namespace struct {
	Name   string // 命名空间名（core / executor）
	Prefix string // CS/本地路径前缀（/core/）
}

// Config storage 业务配置（对应 config.yaml 的 storage 段）。
type Config struct {
	Provider   string      // provider 名（local 或插件名，如 cs）
	MaxSize    int64       // 单文件大小上限（字节）
	Local      Local       // 本地磁盘后端配置
	Namespaces []Namespace // 命名空间白名单
	SignSecret string      // LocalProvider 上传/下载签名密钥
}

// ResolveNamespace 返回命名空间对应的路径前缀。
//
// 命名空间必须在配置白名单中，否则返回 error —— 这是隔离策略的强制点，
// 不允许调用方传任意 namespace 写到别人的目录下。
func (c *Config) ResolveNamespace(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("namespace 不能为空")
	}
	for _, ns := range c.Namespaces {
		if ns.Name == name {
			return ns.Prefix, nil
		}
	}
	return "", fmt.Errorf("未知的 namespace: %s", name)
}

// Load 从 global.PRISM_VP 读取 storage 段并展开环境变量。
// 必须在 core.Viper() 之后调用。
func Load() (*Config, error) {
	vp := global.PRISM_VP
	if vp == nil {
		return nil, fmt.Errorf("config: global.PRISM_VP 未初始化")
	}

	cfg := &Config{
		Provider: vp.GetString("storage.provider"),
		MaxSize:  vp.GetInt64("storage.max-size"),
		Local: Local{
			Dir:     clean(vp.GetString("storage.local.dir")),
			BaseURL: clean(vp.GetString("storage.local.base-url")),
			Expires: vp.GetInt("storage.local.expires"),
		},
		SignSecret: clean(vp.GetString("storage.sign-secret")),
	}

	// 命名空间白名单。
	var nsList []struct {
		Name   string `mapstructure:"name"`
		Prefix string `mapstructure:"prefix"`
	}
	if err := vp.UnmarshalKey("storage.namespaces", &nsList); err != nil {
		return nil, fmt.Errorf("config: 解析 storage.namespaces 失败: %w", err)
	}
	for _, ns := range nsList {
		cfg.Namespaces = append(cfg.Namespaces, Namespace{
			Name:   clean(ns.Name),
			Prefix: clean(ns.Prefix),
		})
	}

	// 环境变量优先覆盖（viper 的 ${VAR} 不一定被展开，显式兜底）。
	cfg.Provider = envDefault("STORAGE_PROVIDER", cfg.Provider, "local")
	cfg.Local.Dir = envDefault("STORAGE_LOCAL_DIR", cfg.Local.Dir, DefaultLocalDir)
	cfg.Local.BaseURL = envDefault("STORAGE_LOCAL_BASE_URL", cfg.Local.BaseURL, "")
	cfg.SignSecret = envDefault("STORAGE_SIGN_SECRET", cfg.SignSecret, "")

	if cfg.MaxSize <= 0 {
		cfg.MaxSize = DefaultMaxSize
	}

	// 命名空间未配置时给出默认的 core/executor 两个，避免开箱即不可用。
	if len(cfg.Namespaces) == 0 {
		cfg.Namespaces = []Namespace{
			{Name: "core", Prefix: "/core/"},
			{Name: "executor", Prefix: "/executor/"},
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// LocalProvider 需要落盘目录存在。
	if cfg.Provider == "local" {
		abs, err := filepath.Abs(cfg.Local.Dir)
		if err != nil {
			return nil, fmt.Errorf("config: 解析 local.dir 绝对路径失败: %w", err)
		}
		cfg.Local.Dir = abs
		if err := os.MkdirAll(cfg.Local.Dir, 0o750); err != nil {
			return nil, fmt.Errorf("config: 创建 local.dir 失败: %w", err)
		}
	}

	return cfg, nil
}

// validate 校验必填项，缺失直接启动失败（fail fast，不静默降级）。
func (c *Config) validate() error {
	switch c.Provider {
	case "local":
		if c.Local.BaseURL == "" {
			return fmt.Errorf("config: provider=local 时 storage.local.base-url 必填")
		}
		if c.SignSecret == "" {
			return fmt.Errorf("config: provider=local 时 storage.sign-secret 必填（用于上传/下载签名）")
		}
	default:
		// 插件后端：必填项由插件自己的 validate 负责（见 provider.Build 报错）
	}

	for _, ns := range c.Namespaces {
		if ns.Name == "" || ns.Prefix == "" {
			return fmt.Errorf("config: namespace 的 name/prefix 都不能为空")
		}
	}
	return nil
}

// clean 去掉 viper 未展开的 ${VAR} 占位符（返回空串），并去掉首尾空白。
func clean(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		// viper 没展开，尝试自己展开 ${VAR} / ${VAR:-default}。
		return expandEnv(s)
	}
	return s
}

// expandEnv 支持 ${VAR} 和 ${VAR:-default} 语法。
func expandEnv(s string) string {
	return os.Expand(s, func(k string) string {
		if i := strings.Index(k, ":-"); i >= 0 {
			key, def := k[:i], k[i+2:]
			if v := os.Getenv(key); v != "" {
				return v
			}
			return def
		}
		return os.Getenv(k)
	})
}

// envDefault 返回环境变量值，空则回退当前值，再空则用 fallback。
func envDefault(key, cur, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if cur != "" {
		return cur
	}
	return fallback
}
