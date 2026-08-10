package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"nucleagent-storage/internal/config"
)

// testCS 返回一份固定的 CS 配置，保证签名可复现。
func testCS() *config.CS {
	return &config.CS{
		Host:       "http://cs.101.com/v0.1",
		CDNHost:    "https://cdncs.101.com/v0.1",
		ServerName: "test_server",
		AccessKey:  "ak_test",
		SecretKey:  "sk_test",
		UserID:     "100000101",
		Scope:      1,
		Expires:    1800,
	}
}

// referenceSign 是 agentia-engine/src/service/cs/cs_storage.go 里签名算法的
// 独立重实现（照抄原逻辑，不复用被测代码），用于交叉验证移植是否等价。
func referenceSign(secret, first, reqPath, method, policyJSON string) string {
	signSource := fmt.Sprintf("%s\n%s\n%s\n%s", first, reqPath, method, policyJSON)
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(signSource))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TestGenerateUploadToken_MatchesAgentiaReference 校验上传签名与 agentia 参考实现一致。
func TestGenerateUploadToken_MatchesAgentiaReference(t *testing.T) {
	cfg := testCS()
	p := NewCSProvider(cfg)

	csFilePath := "/test_server/nucleagent/core/2026/08/abc.txt"
	reqPath := "/v0.1/upload"
	date := "Mon, 10 Aug 2026 06:00:00 GMT"

	token, policyB64 := p.GenerateUploadToken(csFilePath, reqPath, "POST", date)

	// 参考实现的 policy：字段顺序由 encoding/json 对 map 的键排序决定，
	// 两侧都用 map + json.Marshal，故结果必然一致。
	policy := map[string]interface{}{
		"path":       csFilePath,
		"uid":        jsonNumber("100000101"),
		"role":       "admin",
		"policyType": "upload",
		"scope":      1,
	}
	wantBytes, _ := json.Marshal(policy)
	wantSign := referenceSign(cfg.SecretKey, date, reqPath, "POST", string(wantBytes))
	wantToken := fmt.Sprintf("%s:%s:%s", cfg.ServerName, cfg.AccessKey, wantSign)

	if token != wantToken {
		t.Errorf("上传 token 不匹配\n got: %s\nwant: %s", token, wantToken)
	}
	if got, want := policyB64, base64.RawURLEncoding.EncodeToString(wantBytes); got != want {
		t.Errorf("policy base64 不匹配\n got: %s\nwant: %s", got, want)
	}
	// token 必须是 serverName:accessKey:sign 三段结构。
	if parts := strings.Split(token, ":"); len(parts) != 3 {
		t.Errorf("token 结构应为 3 段，实际 %d 段: %s", len(parts), token)
	}
	// base64 必须 URL-safe 且无 padding（CS 服务端要求）。
	if strings.ContainsAny(policyB64, "+/=") {
		t.Errorf("policy base64 必须 URL-safe 无 padding: %s", policyB64)
	}
}

// TestGenerateDownloadToken_MatchesAgentiaReference 校验下载签名与 agentia 参考实现一致。
//
// 下载签名的两个易错点：签名串首段是过期毫秒时间戳（不是日期），
// 请求路径必须带 ?dentryId= 查询串。
func TestGenerateDownloadToken_MatchesAgentiaReference(t *testing.T) {
	cfg := testCS()
	p := NewCSProvider(cfg)

	dentryID := "abc-123-dentry"
	expireAtMs := int64(1786344800000)

	token, policyB64 := p.GenerateDownloadToken(dentryID, expireAtMs)

	policy := map[string]interface{}{
		"dentryId":   dentryID,
		"uid":        jsonNumber("100000101"),
		"role":       "admin",
		"policyType": "download",
	}
	wantBytes, _ := json.Marshal(policy)
	wantSign := referenceSign(cfg.SecretKey,
		fmt.Sprintf("%d", expireAtMs),
		"/v0.1/download?dentryId="+dentryID,
		"GET", string(wantBytes))
	wantToken := fmt.Sprintf("%s:%s:%s", cfg.ServerName, cfg.AccessKey, wantSign)

	if token != wantToken {
		t.Errorf("下载 token 不匹配\n got: %s\nwant: %s", token, wantToken)
	}
	if got, want := policyB64, base64.RawURLEncoding.EncodeToString(wantBytes); got != want {
		t.Errorf("policy base64 不匹配\n got: %s\nwant: %s", got, want)
	}
}

// TestJSONNumber_SerializesAsNumber uid 必须序列化为 JSON 数字而非字符串。
func TestJSONNumber_SerializesAsNumber(t *testing.T) {
	b, err := json.Marshal(map[string]interface{}{"uid": jsonNumber("100000101")})
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}
	if got, want := string(b), `{"uid":100000101}`; got != want {
		t.Errorf("uid 应为裸数字\n got: %s\nwant: %s", got, want)
	}
	// 空 uid 兜底为 0，不能产出非法 JSON。
	b, err = json.Marshal(map[string]interface{}{"uid": jsonNumber("")})
	if err != nil {
		t.Fatalf("空 uid marshal 失败: %v", err)
	}
	if got, want := string(b), `{"uid":0}`; got != want {
		t.Errorf("空 uid 应兜底为 0\n got: %s\nwant: %s", got, want)
	}
}

// TestPresignUpload_BuildsCorrectPathAndFields 校验 CS 上传凭证的路径拼装与表单字段。
func TestPresignUpload_BuildsCorrectPathAndFields(t *testing.T) {
	p := NewCSProvider(testCS())

	cred, err := p.PresignUpload(context.Background(),
		"/nucleagent/core/", "2026/08/abc.txt", "text/plain", 100)
	if err != nil {
		t.Fatalf("PresignUpload 失败: %v", err)
	}

	if cred.Method != "POST" {
		t.Errorf("CS 上传应为 POST，实际 %s", cred.Method)
	}
	if cred.FileField != "filename" {
		t.Errorf("文件字段应为 filename，实际 %s", cred.FileField)
	}
	// 目录字段必须含 serverName 前缀且无重复斜杠。
	if got, want := cred.FormFields["path"], "/test_server/nucleagent/core/2026/08"; got != want {
		t.Errorf("path 字段错误\n got: %s\nwant: %s", got, want)
	}
	if got, want := cred.FormFields["name"], "abc.txt"; got != want {
		t.Errorf("name 字段错误\n got: %s\nwant: %s", got, want)
	}
	if got, want := cred.FormFields["scope"], "1"; got != want {
		t.Errorf("scope 字段错误\n got: %s\nwant: %s", got, want)
	}
	if strings.Contains(strings.TrimPrefix(cred.URL, "http://"), "//") {
		t.Errorf("上传 URL 不应含重复斜杠: %s", cred.URL)
	}
	// 上传 URL 必须带 token/date/policy 三个查询参数。
	u, err := url.Parse(cred.URL)
	if err != nil {
		t.Fatalf("上传 URL 非法: %v", err)
	}
	for _, k := range []string{"token", "date", "policy"} {
		if u.Query().Get(k) == "" {
			t.Errorf("上传 URL 缺少查询参数 %s: %s", k, cred.URL)
		}
	}
	// scope=1（公开）时上传前即可确定下载地址。
	wantStored := "https://cdncs.101.com/v0.1/static/test_server/nucleagent/core/2026/08/abc.txt"
	if cred.StoredURL != wantStored {
		t.Errorf("storedUrl 错误\n got: %s\nwant: %s", cred.StoredURL, wantStored)
	}
}

// TestPresignUpload_PrivateScopeLeavesStoredURLEmpty 私有文件上传前拿不到 dentryId，
// storedUrl 必须留空，由客户端上传后回填。
func TestPresignUpload_PrivateScopeLeavesStoredURLEmpty(t *testing.T) {
	cfg := testCS()
	cfg.Scope = 0
	p := NewCSProvider(cfg)

	cred, err := p.PresignUpload(context.Background(), "/nucleagent/core/", "a.txt", "", 1)
	if err != nil {
		t.Fatalf("PresignUpload 失败: %v", err)
	}
	if cred.StoredURL != "" {
		t.Errorf("私有文件 storedUrl 应留空，实际 %s", cred.StoredURL)
	}
	if got := cred.FormFields["scope"]; got != "0" {
		t.Errorf("私有 scope 应为 0，实际 %s", got)
	}
}

// TestPresignDownload_PrivateFileGetsSignedURL 私有文件应生成带签名的 CDN 下载地址。
func TestPresignDownload_PrivateFileGetsSignedURL(t *testing.T) {
	p := NewCSProvider(testCS())

	got, err := p.PresignDownload(context.Background(), MakeDentryURL("dentry-xyz"))
	if err != nil {
		t.Fatalf("PresignDownload 失败: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("下载 URL 非法: %v", err)
	}
	if u.Host != "cdncs.101.com" {
		t.Errorf("下载应走 CDN 主机，实际 %s", u.Host)
	}
	for _, k := range []string{"dentryId", "token", "policy", "expireAt"} {
		if u.Query().Get(k) == "" {
			t.Errorf("下载 URL 缺少查询参数 %s: %s", k, got)
		}
	}
	if u.Query().Get("dentryId") != "dentry-xyz" {
		t.Errorf("dentryId 错误: %s", u.Query().Get("dentryId"))
	}
}

// TestPresignDownload_PublicURLPassthrough 非 dentry 地址应原样返回。
func TestPresignDownload_PublicURLPassthrough(t *testing.T) {
	p := NewCSProvider(testCS())
	in := "https://cdncs.101.com/v0.1/static/test_server/a.png"
	got, err := p.PresignDownload(context.Background(), in)
	if err != nil {
		t.Fatalf("PresignDownload 失败: %v", err)
	}
	if got != in {
		t.Errorf("公开地址应原样返回\n got: %s\nwant: %s", got, in)
	}
}

// TestDentryURLRoundTrip cs-dentry:// 地址的构造与解析应互逆。
func TestDentryURLRoundTrip(t *testing.T) {
	id := "abc-123"
	if got, ok := ParseDentryURL(MakeDentryURL(id)); !ok || got != id {
		t.Errorf("dentry 往返失败: got=%s ok=%v", got, ok)
	}
	if _, ok := ParseDentryURL("https://example.com/a.png"); ok {
		t.Error("非 dentry 地址不应被解析为 dentry")
	}
}

// TestNormalizeSlashes 压缩重复斜杠时必须保留协议头。
func TestNormalizeSlashes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://cdn.example.com//a//b", "https://cdn.example.com/a/b"},
		{"/a//b///c", "/a/b/c"},
		{"http://h/x", "http://h/x"},
	}
	for _, c := range cases {
		if got := normalizeSlashes(c.in); got != c.want {
			t.Errorf("normalizeSlashes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCSDelete_ReturnsNotSupported CS 不支持删除，必须显式返回 ErrNotSupported
// （而非静默假装成功）。
func TestCSDelete_ReturnsNotSupported(t *testing.T) {
	p := NewCSProvider(testCS())
	if err := p.Delete(context.Background(), MakeDentryURL("x")); err != ErrNotSupported {
		t.Errorf("应返回 ErrNotSupported，实际 %v", err)
	}
}

// TestGetCDNHost_DerivesFromHost 未显式配置 CDN 主机时应从 CS 主机推导。
func TestGetCDNHost_DerivesFromHost(t *testing.T) {
	cfg := &config.CS{Host: "http://cs.101.com/v0.1"}
	if got, want := cfg.GetCDNHost(), "https://cdncs.101.com/v0.1"; got != want {
		t.Errorf("CDN 主机推导错误\n got: %s\nwant: %s", got, want)
	}
}

// TestGetScope_ZeroIsPreserved scope=0（私有）是合法值，不能被默认值逻辑吞掉。
func TestGetScope_ZeroIsPreserved(t *testing.T) {
	if got := (&config.CS{Scope: 0}).GetScope(); got != 0 {
		t.Errorf("显式配置的 scope=0 应保留，实际 %d", got)
	}
	if got := (&config.CS{Scope: -1}).GetScope(); got != 1 {
		t.Errorf("未配置时应默认 scope=1，实际 %d", got)
	}
}
