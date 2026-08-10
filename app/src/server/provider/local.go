package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nucleagent-storage/internal/config"
)

// LocalFilePrefix 本地文件在 DB 中的存储地址前缀。
//
// file:// 后面跟的是**后端逻辑路径**（/nucleagent/core/xxx.png），不是宿主机绝对路径 ——
// 这样换机器/换挂载点后数据仍然可用，落盘时再拼上 local.dir。
const LocalFilePrefix = "file://"

// BlobPath 本地 blob 直传/直取端点的路径前缀。
//
// 这是 LocalProvider 的「存储后端」：客户端 PUT 上传、GET 下载都直连它，
// 元数据 API（/api/v1/files）不碰字节流，与 CS 模式保持同构。
const BlobPath = "/blob"

// LocalProvider 本地磁盘存储后端（开发环境用）。
//
// 同样走 presign 模式：签发带 HMAC-SHA256 签名的 URL，客户端直接 PUT/GET
// 本服务的 /blob 端点，不经过元数据 API 中转。
type LocalProvider struct {
	cfg    *config.Local
	secret []byte
}

// NewLocalProvider 构造本地 Provider。secret 用于 URL 签名。
func NewLocalProvider(cfg *config.Local, secret string) *LocalProvider {
	return &LocalProvider{cfg: cfg, secret: []byte(secret)}
}

// Name 返回后端名。
func (p *LocalProvider) Name() string { return "local" }

// PresignUpload 生成本地上传凭证：一个带签名的 PUT URL。
func (p *LocalProvider) PresignUpload(_ context.Context, prefix, key, contentType string, size int64) (*UploadCredential, error) {
	full := JoinPrefix(prefix, key)
	expiresAt := time.Now().Add(time.Duration(p.cfg.GetExpires()) * time.Second).Unix()

	// 把 size 纳入签名：客户端不能声明小体积换凭证后传大文件。
	signedURL := p.buildSignedURL("PUT", full, expiresAt, size)

	headers := map[string]string{}
	if contentType != "" {
		headers["Content-Type"] = contentType
	}

	return &UploadCredential{
		Method:    "PUT",
		URL:       signedURL,
		Headers:   headers,
		StoredURL: LocalFilePrefix + full,
		ExpiresAt: expiresAt * 1000,
	}, nil
}

// PresignDownload 生成带签名的本地下载 URL。
func (p *LocalProvider) PresignDownload(_ context.Context, storedURL string) (string, error) {
	full, ok := ParseLocalURL(storedURL)
	if !ok {
		if storedURL == "" {
			return "", fmt.Errorf("存储地址为空，无法生成下载链接")
		}
		// 非 file:// 地址（如历史遗留的 http 直链）原样返回。
		return storedURL, nil
	}
	expiresAt := time.Now().Add(time.Duration(p.cfg.GetExpires()) * time.Second).Unix()
	// 下载不限制体积，size 传 0 参与签名。
	return p.buildSignedURL("GET", full, expiresAt, 0), nil
}

// Delete 删除本地磁盘上的文件。文件已不存在视为删除成功（幂等）。
func (p *LocalProvider) Delete(_ context.Context, storedURL string) error {
	full, ok := ParseLocalURL(storedURL)
	if !ok {
		return fmt.Errorf("不是本地存储地址: %s", storedURL)
	}
	abs, err := p.ResolvePath(full)
	if err != nil {
		return err
	}
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除本地文件失败: %w", err)
	}
	return nil
}

// ResolvePath 把后端逻辑路径映射到磁盘绝对路径，并校验未越出 local.dir。
//
// 这是落盘前最后一道防线：即便签名被伪造，也不能写到目录外。
func (p *LocalProvider) ResolvePath(full string) (string, error) {
	rel := strings.TrimPrefix(filepath.ToSlash(full), "/")
	if rel == "" {
		return "", fmt.Errorf("空的对象路径")
	}
	root, err := filepath.Abs(p.cfg.Dir)
	if err != nil {
		return "", fmt.Errorf("解析存储根目录失败: %w", err)
	}
	abs := filepath.Clean(filepath.Join(root, filepath.FromSlash(rel)))
	// 必须严格位于 root 之下（用 separator 结尾比较，避免 /data/uploads-evil 误通过）。
	if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("对象路径越出存储根目录: %s", full)
	}
	return abs, nil
}

// MaxSizeLimit 返回配置的单文件上限，供 blob handler 复核。
// 由 handler 侧持有配置，这里不重复存。

// buildSignedURL 构造带 expires/max/sig 查询参数的签名 URL。
func (p *LocalProvider) buildSignedURL(method, full string, expiresAt, size int64) string {
	sig := p.Sign(method, full, expiresAt, size)
	base := strings.TrimRight(p.cfg.BaseURL, "/")
	// full 已以 / 开头；对每段做 URL 转义，保证含空格/中文的文件名可用。
	return fmt.Sprintf("%s%s%s?expires=%d&max=%d&sig=%s",
		base, BlobPath, escapePath(full), expiresAt, size, url.QueryEscape(sig))
}

// Sign 计算 HMAC-SHA256 签名。
//
// 签名串绑定 method/path/expires/size 四要素：
// 换方法、换路径、改过期时间、改体积上限都会导致签名失效。
func (p *LocalProvider) Sign(method, full string, expiresAt, size int64) string {
	payload := strings.Join([]string{
		method,
		full,
		strconv.FormatInt(expiresAt, 10),
		strconv.FormatInt(size, 10),
	}, "\n")
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify 校验签名与有效期。返回 nil 表示放行。
//
// 用 hmac.Equal 做常数时间比较，避免时序侧信道。
func (p *LocalProvider) Verify(method, full string, expiresAt, size int64, sig string) error {
	if time.Now().Unix() > expiresAt {
		return fmt.Errorf("签名已过期")
	}
	expected := p.Sign(method, full, expiresAt, size)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return fmt.Errorf("签名校验失败")
	}
	return nil
}

// MakeLocalURL 由后端逻辑路径构造入库用的 file:// 地址。
func MakeLocalURL(full string) string {
	return LocalFilePrefix + full
}

// ParseLocalURL 从 file:// 地址提取后端逻辑路径。非本地地址返回 ("", false)。
func ParseLocalURL(storedURL string) (string, bool) {
	if strings.HasPrefix(storedURL, LocalFilePrefix) {
		return strings.TrimPrefix(storedURL, LocalFilePrefix), true
	}
	return "", false
}

// escapePath 逐段转义路径，保留 / 分隔符。
func escapePath(full string) string {
	parts := strings.Split(full, "/")
	for i, seg := range parts {
		parts[i] = url.PathEscape(seg)
	}
	return strings.Join(parts, "/")
}
