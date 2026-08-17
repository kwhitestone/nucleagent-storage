package svc

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kwhitestone/nucleagent-storage/provider"
)

// TestBuildObjectKey_Format 对象路径必须是 {yyyy}/{mm}/{fileId}/{filename}。
//
// fileId 单独占一层是同名隔离的前提：两个都叫 report.pdf 的文件
// 落在各自的 fileId 目录下，不会互相覆盖。
func TestBuildObjectKey_Format(t *testing.T) {
	const fileID = "11111111-2222-3333-4444-555555555555"

	got, err := buildObjectKey(fileID, "report.pdf")
	if err != nil {
		t.Fatalf("buildObjectKey 失败: %v", err)
	}

	parts := strings.Split(got, "/")
	if len(parts) != 4 {
		t.Fatalf("对象路径应为 4 段 {yyyy}/{mm}/{fileId}/{name}，实际 %d 段: %s", len(parts), got)
	}
	if len(parts[0]) != 4 {
		t.Errorf("第 1 段应为 4 位年份，实际 %q", parts[0])
	}
	if len(parts[1]) != 2 {
		t.Errorf("第 2 段应为 2 位月份（补零），实际 %q", parts[1])
	}
	if parts[2] != fileID {
		t.Errorf("第 3 段应为 fileId\n got: %s\nwant: %s", parts[2], fileID)
	}
	if parts[3] != "report.pdf" {
		t.Errorf("第 4 段应为原始文件名，实际 %q", parts[3])
	}
}

// TestBuildObjectKey_SameNameIsolated 同名文件必须落在不同路径（靠 fileId 目录隔离）。
func TestBuildObjectKey_SameNameIsolated(t *testing.T) {
	a, err := buildObjectKey("file-id-aaa", "report.pdf")
	if err != nil {
		t.Fatalf("buildObjectKey 失败: %v", err)
	}
	b, err := buildObjectKey("file-id-bbb", "report.pdf")
	if err != nil {
		t.Fatalf("buildObjectKey 失败: %v", err)
	}
	if a == b {
		t.Errorf("同名不同 fileId 的对象路径必须不同，却都是 %s", a)
	}
	// 但文件名部分应保持一致（下载时才有正确的保存名）。
	if !strings.HasSuffix(a, "/report.pdf") || !strings.HasSuffix(b, "/report.pdf") {
		t.Errorf("两者都应以 /report.pdf 结尾: %s, %s", a, b)
	}
}

// TestBuildObjectKey_RejectsTraversal 带路径穿越的文件名必须被清洗掉目录成分，
// 绝不能让 key 逃出命名空间前缀。
func TestBuildObjectKey_RejectsTraversal(t *testing.T) {
	cases := []string{
		"../../../etc/passwd",
		"..\\..\\windows\\system32\\cmd.exe",
		"/etc/shadow",
		"a/b/c/evil.sh",
	}
	for _, in := range cases {
		got, err := buildObjectKey("fid", in)
		if err != nil {
			// 直接拒绝也是可接受的结果。
			continue
		}
		if strings.Contains(got, "..") {
			t.Errorf("对象路径仍含 ..：输入 %q → %q", in, got)
		}
		// 清洗后必须仍是 4 段（目录成分被压成单个文件名）。
		if n := len(strings.Split(got, "/")); n != 4 {
			t.Errorf("输入 %q 清洗后应为 4 段，实际 %d 段: %s", in, n, got)
		}
	}
}

// TestSanitizeFileName 文件名清洗的各类边界。
func TestSanitizeFileName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"普通文件名原样保留", "report.pdf", "report.pdf"},
		{"中文文件名保留", "季度报告.pdf", "季度报告.pdf"},
		{"丢掉目录成分", "a/b/report.pdf", "report.pdf"},
		{"反斜杠目录成分", `C:\tmp\report.pdf`, "report.pdf"},
		{"路径穿越被压平", "../../etc/passwd", "passwd"},
		{"空格转下划线", "my report.pdf", "my_report.pdf"},
		{"问号井号被替换", "a?b#c.pdf", "a_b_c.pdf"},
		{"空文件名兜底", "", "file"},
		{"单个点兜底", ".", "file"},
		{"双点兜底", "..", "file"},
		{"无扩展名", "README", "README"},
		{"隐藏文件保留主干", ".gitignore", "gitignore"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeFileName(c.in); got != c.want {
				t.Errorf("sanitizeFileName(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestSanitizeFileName_NoDangerousChars 清洗结果绝不能含路径分隔符或控制字符。
//
// 这是硬约束：文件名会进 CS 的签名 policy path，也会进 URL。
func TestSanitizeFileName_NoDangerousChars(t *testing.T) {
	inputs := []string{
		"a/b.txt", `a\b.txt`, "a\x00b.txt", "a\nb.txt", "a\tb.txt",
		"a%2Fb.txt", `a"b'.txt`, "a<b>c|d:e*f.txt", "a\x7fb.txt",
	}
	for _, in := range inputs {
		got := sanitizeFileName(in)
		if strings.ContainsAny(got, "/\\?#%\"'<>|:* \x00\n\t\x7f") {
			t.Errorf("sanitizeFileName(%q) = %q，仍含危险字符", in, got)
		}
		if got == "" {
			t.Errorf("sanitizeFileName(%q) 返回空串", in)
		}
	}
}

// TestSanitizeFileName_LongNameTruncatedKeepingExt 超长文件名截断主干但保留扩展名。
//
// 扩展名决定 CDN 推断的 Content-Type，是不能丢的部分。
func TestSanitizeFileName_LongNameTruncatedKeepingExt(t *testing.T) {
	long := strings.Repeat("a", 500) + ".pdf"
	got := sanitizeFileName(long)

	if len(got) > maxStoredFileNameLen {
		t.Errorf("清洗后长度 %d 超过上限 %d", len(got), maxStoredFileNameLen)
	}
	if !strings.HasSuffix(got, ".pdf") {
		t.Errorf("截断后必须保留扩展名，实际 %q", got)
	}
}

// TestSanitizeFileName_TruncationKeepsValidUTF8 截断中文名不能切出半个字符。
//
// 中文文件名极常见，按字节截断若不对齐 rune 边界会产生非法 UTF-8，
// 进而让 JSON 序列化/签名产生乱码。
func TestSanitizeFileName_TruncationKeepsValidUTF8(t *testing.T) {
	long := strings.Repeat("报", 200) + ".pdf"
	got := sanitizeFileName(long)

	if !utf8.ValidString(got) {
		t.Errorf("截断产生了非法 UTF-8: %q", got)
	}
	if len(got) > maxStoredFileNameLen {
		t.Errorf("清洗后长度 %d 超过上限 %d", len(got), maxStoredFileNameLen)
	}
	if !strings.HasSuffix(got, ".pdf") {
		t.Errorf("截断后应保留扩展名，实际 %q", got)
	}
}

// TestResolveStoredURL 注册时存储地址的优先级与收敛规则。
func TestResolveStoredURL(t *testing.T) {
	cases := []struct {
		name     string
		in       RegisterInput
		existing string
		want     string
	}{
		{
			name: "dentryId 优先于一切",
			in:   RegisterInput{DentryID: "d-1", StoredURL: "https://x/y.png"},
			want: "cs-dentry://d-1",
		},
		{
			name: "dentryId 会被转成 cs-dentry 形态",
			in:   RegisterInput{DentryID: "abc-123"},
			want: "cs-dentry://abc-123",
		},
		{
			name: "无 dentryId 时用客户端回传的 storedUrl",
			in:   RegisterInput{StoredURL: "https://cdn/x.png"},
			want: "https://cdn/x.png",
		},
		{
			name: "签名下载 URL 收敛回 cs-dentry",
			in:   RegisterInput{StoredURL: "https://gcdncs.101.com/v0.1/download?dentryId=d-9&token=t&expireAt=1"},
			want: "cs-dentry://d-9",
		},
		{
			name:     "都没传则沿用 presign 预置值",
			in:       RegisterInput{},
			existing: "file:///nucleagent/core/a.png",
			want:     "file:///nucleagent/core/a.png",
		},
		{
			name:     "全空返回空串（调用方据此拒绝）",
			in:       RegisterInput{},
			existing: "",
			want:     "",
		},
		{
			name: "纯空白的 dentryId 视为未提供",
			in:   RegisterInput{DentryID: "   ", StoredURL: "https://cdn/x.png"},
			want: "https://cdn/x.png",
		},
	}
	// 用 CS 插件的语义 fake：dentryId → cs-dentry://，签名 URL → 收敛回 dentry 形态。
	// 主框架只依赖可选接口（RefMaker / StoredURLNormalizer），不感知 CS 细节。
	prv := &fakeRefProvider{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveStoredURL(prv, c.in, c.existing); got != c.want {
				t.Errorf("resolveStoredURL() = %q, want %q", got, c.want)
			}
		})
	}
}

type fakeRefProvider struct{ baseProvider }

// MakeRefURL 实现 provider.RefMaker。
func (f *fakeRefProvider) MakeRefURL(refID string) string { return "cs-dentry://" + refID }

// NormalizeStoredURL 实现 provider.StoredURLNormalizer。
func (f *fakeRefProvider) NormalizeStoredURL(stored string) string {
	if id := extractDentryIDFromURL(stored); id != "" {
		return "cs-dentry://" + id
	}
	return stored
}

// baseProvider 最小 Provider 实现（供测试嵌入）。
type baseProvider struct{}

func (baseProvider) Name() string { return "fake" }
func (baseProvider) PresignUpload(ctx context.Context, prefix, key, contentType string, size int64) (*provider.UploadCredential, error) {
	return nil, fmt.Errorf("fake: 不支持")
}
func (baseProvider) PresignDownload(ctx context.Context, storedURL string) (string, error) {
	return "", fmt.Errorf("fake: 不支持")
}
func (baseProvider) Delete(ctx context.Context, storedURL string) error { return provider.ErrNotSupported }

// extractDentryIDFromURL 从签名下载 URL 的查询串提取 dentryId。
func extractDentryIDFromURL(stored string) string {
	u, err := url.Parse(stored)
	if err != nil {
		return ""
	}
	return u.Query().Get("dentryId")
}

// TestGuessContentType 扩展名推断 MIME，未知类型兜底为通用二进制。
func TestGuessContentType(t *testing.T) {
	if got := guessContentType("a.unknownext123"); got != "application/octet-stream" {
		t.Errorf("未知扩展名应兜底为 application/octet-stream，实际 %s", got)
	}
	if got := guessContentType("a.json"); !strings.Contains(got, "json") {
		t.Errorf(".json 应推断出 json 类型，实际 %s", got)
	}
}

// TestBuildObjectKey_MonthIsZeroPadded 月份必须补零，否则字典序排序会错乱。
func TestBuildObjectKey_MonthIsZeroPadded(t *testing.T) {
	got, err := buildObjectKey("fid", "a.txt")
	if err != nil {
		t.Fatalf("buildObjectKey 失败: %v", err)
	}
	month := strings.Split(got, "/")[1]
	if len(month) != 2 {
		t.Errorf("月份应补零为 2 位，实际 %q（完整路径 %s）", month, got)
	}
	var m int
	if _, err := fmt.Sscanf(month, "%d", &m); err != nil || m < 1 || m > 12 {
		t.Errorf("月份 %q 不是合法月份", month)
	}
}
