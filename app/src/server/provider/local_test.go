package provider

import (
	"context"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kwhitestone/nucleagent-storage/internal/config"
)

func testLocal(t *testing.T) (*LocalProvider, string) {
	t.Helper()
	dir := t.TempDir()
	return NewLocalProvider(&config.Local{
		Dir:     dir,
		BaseURL: "http://localhost:26610",
		Expires: 1800,
	}, "test-secret"), dir
}

// TestLocalPresignUpload_ProducesVerifiableSignature presign 出来的 URL 必须能被 Verify 通过。
func TestLocalPresignUpload_ProducesVerifiableSignature(t *testing.T) {
	p, _ := testLocal(t)

	cred, err := p.PresignUpload(context.Background(), "/nucleagent/core/", "2026/08/a.txt", "text/plain", 1234)
	if err != nil {
		t.Fatalf("PresignUpload 失败: %v", err)
	}
	if cred.Method != "PUT" {
		t.Errorf("本地上传应为 PUT，实际 %s", cred.Method)
	}
	if want := "file:///nucleagent/core/2026/08/a.txt"; cred.StoredURL != want {
		t.Errorf("storedUrl 错误\n got: %s\nwant: %s", cred.StoredURL, want)
	}

	u, err := url.Parse(cred.URL)
	if err != nil {
		t.Fatalf("上传 URL 非法: %v", err)
	}
	// 服务端会用解码后的路径重算签名，此处模拟同一流程。
	full, _ := url.PathUnescape(strings.TrimPrefix(u.EscapedPath(), BlobPath))
	expires := mustAtoi(t, u.Query().Get("expires"))
	max := mustAtoi(t, u.Query().Get("max"))

	if err := p.Verify("PUT", full, expires, max, u.Query().Get("sig")); err != nil {
		t.Errorf("presign 生成的签名应能通过校验: %v", err)
	}
	// max 必须等于 presign 时声明的体积（上传限额的依据）。
	if max != 1234 {
		t.Errorf("max 应为声明体积 1234，实际 %d", max)
	}
}

// TestLocalSignature_RejectsTampering 任一签名要素被改动都应导致校验失败。
func TestLocalSignature_RejectsTampering(t *testing.T) {
	p, _ := testLocal(t)
	full := "/nucleagent/core/a.txt"
	exp := time.Now().Add(time.Hour).Unix()
	sig := p.Sign("PUT", full, exp, 100)

	cases := []struct {
		name          string
		method, path  string
		expires, size int64
		sig           string
	}{
		{"换方法", "GET", full, exp, 100, sig},
		{"换路径", "PUT", "/nucleagent/executor/a.txt", exp, 100, sig},
		{"改过期时间", "PUT", full, exp + 1, 100, sig},
		{"改体积上限", "PUT", full, exp, 999999, sig},
		{"伪造签名", "PUT", full, exp, 100, "forged"},
		{"空签名", "PUT", full, exp, 100, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := p.Verify(c.method, c.path, c.expires, c.size, c.sig); err == nil {
				t.Errorf("%s 应导致签名校验失败，但通过了", c.name)
			}
		})
	}
}

// TestLocalSignature_RejectsExpired 过期签名必须拒绝。
func TestLocalSignature_RejectsExpired(t *testing.T) {
	p, _ := testLocal(t)
	full := "/nucleagent/core/a.txt"
	past := time.Now().Add(-time.Hour).Unix()
	sig := p.Sign("GET", full, past, 0)

	err := p.Verify("GET", full, past, 0, sig)
	if err == nil {
		t.Fatal("过期签名应被拒绝")
	}
	if !strings.Contains(err.Error(), "过期") {
		t.Errorf("错误信息应指明过期，实际: %v", err)
	}
}

// TestLocalSignature_DifferentSecretsDontVerify 换密钥后旧签名必须失效。
func TestLocalSignature_DifferentSecretsDontVerify(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Local{Dir: dir, BaseURL: "http://localhost:26610", Expires: 1800}
	p1 := NewLocalProvider(cfg, "secret-one")
	p2 := NewLocalProvider(cfg, "secret-two")

	exp := time.Now().Add(time.Hour).Unix()
	sig := p1.Sign("GET", "/a.txt", exp, 0)
	if err := p2.Verify("GET", "/a.txt", exp, 0, sig); err == nil {
		t.Error("不同密钥签发的签名不应互相通过")
	}
}

// TestResolvePath_BlocksTraversal 路径穿越必须在落盘前被拦下。
//
// 这是签名之外的第二道防线：即便签名被伪造，也不能写到 dir 之外。
func TestResolvePath_BlocksTraversal(t *testing.T) {
	p, dir := testLocal(t)

	bad := []string{
		"/../../../etc/passwd",
		"/../uploads-evil/secret.txt", // 兄弟目录前缀逃逸
		"/nucleagent/../../../etc/shadow",
		"/..",
	}
	for _, in := range bad {
		t.Run(in, func(t *testing.T) {
			if got, err := p.ResolvePath(in); err == nil {
				t.Errorf("穿越路径 %q 应被拒绝，却解析为 %s", in, got)
			}
		})
	}

	// 正常路径必须解析到 dir 之内。
	got, err := p.ResolvePath("/nucleagent/core/a.txt")
	if err != nil {
		t.Fatalf("合法路径不应报错: %v", err)
	}
	root, _ := filepath.Abs(dir)
	if !strings.HasPrefix(got, root+string(filepath.Separator)) {
		t.Errorf("合法路径应落在 %s 之内，实际 %s", root, got)
	}
}

// TestLocalURLRoundTrip file:// 地址的构造与解析应互逆。
func TestLocalURLRoundTrip(t *testing.T) {
	full := "/nucleagent/core/a.txt"
	if got, ok := ParseLocalURL(MakeLocalURL(full)); !ok || got != full {
		t.Errorf("file:// 往返失败: got=%s ok=%v", got, ok)
	}
	if _, ok := ParseLocalURL("ref://x"); ok {
		t.Error("非本地 scheme 地址不应被解析为本地地址")
	}
}

// TestPresignUpload_HandlesSpecialFilenames 含空格/中文的文件名必须正确转义且签名可校验。
func TestPresignUpload_HandlesSpecialFilenames(t *testing.T) {
	p, _ := testLocal(t)

	for _, key := range []string{"2026/08/我的 文件.txt", "2026/08/a b+c&d.png"} {
		t.Run(key, func(t *testing.T) {
			cred, err := p.PresignUpload(context.Background(), "/nucleagent/core/", key, "", 10)
			if err != nil {
				t.Fatalf("PresignUpload 失败: %v", err)
			}
			u, err := url.Parse(cred.URL)
			if err != nil {
				t.Fatalf("URL 非法: %v", err)
			}
			// 走与 blob handler 相同的还原路径，确认签名对得上。
			full, err := url.PathUnescape(strings.TrimPrefix(u.EscapedPath(), BlobPath))
			if err != nil {
				t.Fatalf("路径解码失败: %v", err)
			}
			if err := p.Verify("PUT", full,
				mustAtoi(t, u.Query().Get("expires")),
				mustAtoi(t, u.Query().Get("max")),
				u.Query().Get("sig")); err != nil {
				t.Errorf("特殊文件名的签名应可校验: %v", err)
			}
		})
	}
}

// TestSanitizeKey 对象路径清洗：穿越与空值必须拒绝，合法路径规整后返回。
func TestSanitizeKey(t *testing.T) {
	bad := []string{"", "  ", "..", "../x", "../../etc/passwd", "/", "a/../../../b"}
	for _, in := range bad {
		if got, err := SanitizeKey(in); err == nil {
			t.Errorf("SanitizeKey(%q) 应报错，却返回 %q", in, got)
		}
	}
	good := map[string]string{
		"2026/08/a.txt":   "2026/08/a.txt",
		"/2026/08/a.txt/": "2026/08/a.txt",
		"a//b/c.txt":      "a/b/c.txt",
		"a/./b.txt":       "a/b.txt",
		"a/b/../c.txt":    "a/c.txt",
	}
	for in, want := range good {
		got, err := SanitizeKey(in)
		if err != nil {
			t.Errorf("SanitizeKey(%q) 不应报错: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("SanitizeKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestJoinPrefix 前缀拼接不得产生重复斜杠。
func TestJoinPrefix(t *testing.T) {
	cases := []struct{ prefix, key, want string }{
		{"/nucleagent/core/", "a.txt", "/nucleagent/core/a.txt"},
		{"nucleagent/core", "a.txt", "/nucleagent/core/a.txt"},
		{"/", "a.txt", "/a.txt"},
	}
	for _, c := range cases {
		if got := JoinPrefix(c.prefix, c.key); got != c.want {
			t.Errorf("JoinPrefix(%q,%q) = %q, want %q", c.prefix, c.key, got, c.want)
		}
	}
}

// TestLocalDelete_IsIdempotent 删除不存在的文件不应报错（幂等）。
func TestLocalDelete_IsIdempotent(t *testing.T) {
	p, _ := testLocal(t)
	if err := p.Delete(context.Background(), MakeLocalURL("/nucleagent/core/missing.txt")); err != nil {
		t.Errorf("删除不存在的文件应幂等成功，实际: %v", err)
	}
	// 非本地地址应报错（避免把其它后端地址误当本地路径删）。
	if err := p.Delete(context.Background(), "ref://x"); err == nil {
		t.Error("删除非本地地址应报错")
	}
}

// mustAtoi 解析查询参数里的整数，失败即测试失败。
func mustAtoi(t *testing.T, s string) int64 {
	t.Helper()
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatalf("解析整数 %q 失败: %v", s, err)
	}
	return v
}
