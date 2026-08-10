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
	"time"

	"nucleagent-storage/internal/config"
)

// CSDentryPrefix 私有 CS 文件在 DB 中的存储地址前缀（按 dentryId 索引）。
const CSDentryPrefix = "cs-dentry://"

// CSProvider CS（cs.101.com）存储后端。
//
// 签名逻辑移植自 agentia-engine/src/service/cs/cs_storage.go，
// 去掉了对 agentia config/global 的依赖，自包含。
//
// 关键：本 Provider 只算签名，不发任何上传/下载请求 —— 客户端拿凭证直连 CS。
type CSProvider struct {
	cfg *config.CS
}

// NewCSProvider 构造 CS Provider。
func NewCSProvider(cfg *config.CS) *CSProvider {
	return &CSProvider{cfg: cfg}
}

// Name 返回后端名。
func (p *CSProvider) Name() string { return "cs" }

// csDateFormat CS 签名要求的 RFC1123 GMT 时间格式。
const csDateFormat = "Mon, 02 Jan 2006 15:04:05 GMT"

// jsonNumber 让 uid 以 JSON 数字（而非字符串）序列化，与 CS 服务端 policy 校验一致。
type jsonNumber string

// MarshalJSON 输出裸数字字面量；空值输出 0。
func (n jsonNumber) MarshalJSON() ([]byte, error) {
	if n == "" {
		return []byte("0"), nil
	}
	return []byte(string(n)), nil
}

// GenerateUploadToken 生成 CS 上传 token 与 base64 policy。
//
// 签名串格式："{date}\n{reqPath}\n{method}\n{policyJSON}"，HMAC-SHA1(SecretKey)。
// token 格式："{serverName}:{accessKey}:{sign}"。
//
// 参数：
//   - csFilePath CS 上的完整文件路径（/server_name/dir/file.txt）
//   - reqURLPath 请求路径（/v0.1/upload）
//   - method     HTTP 方法（POST）
//   - dateGMT    RFC1123 GMT 格式时间
func (p *CSProvider) GenerateUploadToken(csFilePath, reqURLPath, method, dateGMT string) (string, string) {
	policy := map[string]interface{}{
		"path":       csFilePath,
		"uid":        jsonNumber(p.cfg.GetUserID()),
		"role":       "admin",
		"policyType": "upload",
		"scope":      p.cfg.GetScope(),
	}
	return p.sign(policy, dateGMT, reqURLPath, method)
}

// GenerateDownloadToken 生成 CS 私有文件下载 token 与 base64 policy。
//
// 与上传的差异：签名串首段是过期毫秒时间戳（而非日期），policyType=download，
// 请求路径带 dentryId 查询串。
func (p *CSProvider) GenerateDownloadToken(dentryID string, expireAtMs int64) (string, string) {
	policy := map[string]interface{}{
		"dentryId":   dentryID,
		"uid":        jsonNumber(p.cfg.GetUserID()),
		"role":       "admin",
		"policyType": "download",
	}
	reqURLPath := "/v0.1/download?dentryId=" + dentryID
	return p.sign(policy, fmt.Sprintf("%d", expireAtMs), reqURLPath, "GET")
}

// sign 计算 HMAC-SHA1 签名，返回 (token, policyBase64)。
//
// policy 的 JSON 必须与签名串里用的完全一致（同一份 marshal 结果），
// 否则服务端重算签名会不匹配。
func (p *CSProvider) sign(policy map[string]interface{}, first, reqURLPath, method string) (string, string) {
	policyBytes, _ := json.Marshal(policy)
	policyStr := string(policyBytes)
	// URL-safe base64 且不带 padding（对齐 CS 服务端的 replace('=','')）。
	policyBase64 := base64.RawURLEncoding.EncodeToString(policyBytes)

	signSource := fmt.Sprintf("%s\n%s\n%s\n%s", first, reqURLPath, method, policyStr)

	mac := hmac.New(sha1.New, []byte(p.cfg.SecretKey))
	mac.Write([]byte(signSource))
	sign := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	token := fmt.Sprintf("%s:%s:%s", p.cfg.ServerName, p.cfg.AccessKey, sign)
	return token, policyBase64
}

// PresignUpload 生成 CS 上传凭证。客户端拿到后直接 POST multipart 到 URL。
func (p *CSProvider) PresignUpload(_ context.Context, prefix, key, _ string, _ int64) (*UploadCredential, error) {
	// CS 路径规则：/{serverName}/{prefix}/{key}
	full := JoinPrefix(prefix, key)
	csFilePath := normalizeSlashes("/" + p.cfg.ServerName + full)
	csDir := csFilePath[:strings.LastIndex(csFilePath, "/")]
	if csDir == "" {
		csDir = "/"
	}
	fileName := csFilePath[strings.LastIndex(csFilePath, "/")+1:]

	reqURLPath := "/v0.1/upload"
	now := time.Now().UTC()
	dateGMT := now.Format(csDateFormat)

	token, policyBase64 := p.GenerateUploadToken(csFilePath, reqURLPath, "POST", dateGMT)

	uploadURL := fmt.Sprintf("%s/upload?token=%s&date=%s&policy=%s",
		p.cfg.GetHost(),
		url.QueryEscape(token),
		url.QueryEscape(dateGMT),
		policyBase64,
	)

	cred := &UploadCredential{
		Method:    "POST",
		URL:       uploadURL,
		FileField: "filename",
		FormFields: map[string]string{
			"path":  csDir,
			"name":  fileName,
			"scope": fmt.Sprintf("%d", p.cfg.GetScope()),
		},
		ExpiresAt: now.Add(time.Duration(p.cfg.GetExpires()) * time.Second).UnixMilli(),
	}

	// scope!=0（公开）时下载地址上传前即可确定，直接给出静态 CDN 地址；
	// 私有文件（scope=0）必须等 CS 返回 dentry_id 才知道地址，留空由客户端回填。
	if p.cfg.GetScope() != 0 {
		cred.StoredURL = normalizeSlashes(p.cfg.GetCDNHost() + "/static/" + p.cfg.ServerName + full) //nolint:gocritic // host 含 :// 由 normalizeSlashes 保护
	}

	return cred, nil
}

// PresignDownload 把存储地址转成客户端可直接 GET 的 URL。
//
//   - cs-dentry://xxx → 生成带 token/policy/expireAt 的 CDN 签名 URL
//   - 其它（已是 http(s) 公开地址）→ 原样返回
func (p *CSProvider) PresignDownload(_ context.Context, storedURL string) (string, error) {
	dentryID, ok := ParseDentryURL(storedURL)
	if !ok {
		if storedURL == "" {
			return "", fmt.Errorf("存储地址为空，无法生成下载链接")
		}
		return storedURL, nil
	}

	expireAtMs := time.Now().Add(time.Duration(p.cfg.GetExpires()) * time.Second).UnixMilli()
	token, policyBase64 := p.GenerateDownloadToken(dentryID, expireAtMs)

	return fmt.Sprintf("%s/download?dentryId=%s&token=%s&policy=%s&expireAt=%d",
		p.cfg.GetCDNHost(),
		url.QueryEscape(dentryID),
		url.QueryEscape(token),
		policyBase64,
		expireAtMs,
	), nil
}

// Delete CS 侧删除。
//
// CS 未开放本服务可用的删除签名接口，故此处不支持 —— 上层只做 DB 软删除。
// 返回 ErrNotSupported 让调用方显式处理，不静默假装成功。
func (p *CSProvider) Delete(_ context.Context, _ string) error {
	return ErrNotSupported
}

// MakeDentryURL 由 dentryId 构造入库用的 cs-dentry:// 地址。
func MakeDentryURL(dentryID string) string {
	return CSDentryPrefix + dentryID
}

// ParseDentryURL 从 cs-dentry:// 地址提取 dentryId。非 dentry 地址返回 ("", false)。
func ParseDentryURL(storedURL string) (string, bool) {
	if strings.HasPrefix(storedURL, CSDentryPrefix) {
		return strings.TrimPrefix(storedURL, CSDentryPrefix), true
	}
	return "", false
}

// normalizeSlashes 压掉路径中的重复斜杠，但保留协议头的 "://"。
func normalizeSlashes(s string) string {
	scheme := ""
	if i := strings.Index(s, "://"); i >= 0 {
		scheme = s[:i+3]
		s = s[i+3:]
	}
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	return scheme + s
}
