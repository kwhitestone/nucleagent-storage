package config

import "testing"

// TestValidate_UnknownProvider_DeferredToRegistry 未知 provider 名不再由 config 拒绝
// —— 插件后端的合法性由 provider.Build 的注册表判定，config 只管 local 自身的必填项。
// （config 包不 import provider，避免循环依赖。）
func TestValidate_UnknownProvider_DeferredToRegistry(t *testing.T) {
	c := &Config{Provider: "cs", Namespaces: []Namespace{{Name: "cs", Prefix: "/x/"}}}
	if err := c.validate(); err != nil {
		t.Errorf("插件 provider 名应放行到注册表判定，实际报错: %v", err)
	}
}

// TestResolveNamespace 命名空间白名单是隔离策略的强制点。
func TestResolveNamespace(t *testing.T) {
	c := &Config{Namespaces: []Namespace{
		{Name: "core", Prefix: "/nucleagent/core/"},
		{Name: "executor", Prefix: "/nucleagent/executor/"},
	}}

	if got, err := c.ResolveNamespace("core"); err != nil || got != "/nucleagent/core/" {
		t.Errorf("core 应解析为 /core/，实际 %q (err=%v)", got, err)
	}
	// 白名单外的命名空间必须被拒 —— 否则调用方能写到任意目录。
	if _, err := c.ResolveNamespace("evil"); err == nil {
		t.Error("未知 namespace 必须报错")
	}
	if _, err := c.ResolveNamespace(""); err == nil {
		t.Error("空 namespace 必须报错")
	}
}

// TestExpandEnv 支持 ${VAR} 与 ${VAR:-default} 两种语法。
//
// config.yaml 里大量使用 ${SOME_ACCESS_KEY} 这类占位符，viper 不一定展开，
// 展开逻辑出错会让凭据变成字面量 "${SOME_ACCESS_KEY}" 而非空值，
// 从而绕过 validate 的必填校验。
func TestExpandEnv(t *testing.T) {
	t.Setenv("CFG_TEST_SET", "real-value")

	cases := []struct{ in, want string }{
		{"${CFG_TEST_SET}", "real-value"},
		{"${CFG_TEST_SET:-fallback}", "real-value"},
		{"${CFG_TEST_UNSET_XYZ:-fallback}", "fallback"},
		{"${CFG_TEST_UNSET_XYZ}", ""},
	}
	for _, c := range cases {
		if got := expandEnv(c.in); got != c.want {
			t.Errorf("expandEnv(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestClean_UnexpandedPlaceholderBecomesEmpty 未展开的 ${VAR} 必须变成空串，
// 而不是字面量 —— 否则 validate 会把占位符当成"已配置"，放行一份坏配置。
func TestClean_UnexpandedPlaceholderBecomesEmpty(t *testing.T) {
	if got := clean("${DEFINITELY_UNSET_VAR_XYZ}"); got != "" {
		t.Errorf("未设置的占位符应清成空串，实际 %q", got)
	}
	if got := clean("  literal-value  "); got != "literal-value" {
		t.Errorf("普通值应去掉首尾空白，实际 %q", got)
	}
}

