package svc

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"github.com/kwhitestone/prism-fusion/global"

	"github.com/kwhitestone/nucleagent-storage/internal/config"
	"github.com/kwhitestone/nucleagent-storage/provider"
)

// 业务错误，供 router 层映射到 HTTP 状态码。
var (
	// ErrNotFound 文件不存在。
	ErrNotFound = errors.New("文件不存在")
	// ErrTooLarge 超过配置的单文件上限。
	ErrTooLarge = errors.New("文件超过大小上限")
	// ErrForbidden 跨命名空间访问。
	ErrForbidden = errors.New("无权访问该文件")
)

// Service 文件元数据服务。
type Service struct {
	cfg *config.Config
	prv provider.Provider
}

// NewService 构造服务。
func NewService(cfg *config.Config, prv provider.Provider) *Service {
	return &Service{cfg: cfg, prv: prv}
}

// Provider 返回底层存储后端（供 blob handler 复用本地路径解析）。
func (s *Service) Provider() provider.Provider { return s.prv }

// Config 返回业务配置。
func (s *Service) Config() *config.Config { return s.cfg }

// db 返回 GORM 句柄，未初始化时报错而非 panic。
func (s *Service) db() (*gorm.DB, error) {
	if global.PRISM_DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return global.PRISM_DB, nil
}

// PresignResult presign 的返回值。
type PresignResult struct {
	FileID     string                     `json:"fileId"`
	ObjectKey  string                     `json:"objectKey"`
	Credential *provider.UploadCredential `json:"credential"`
}

// Presign 生成上传凭证，并落一条 pending 记录占位。
//
// 落 pending 记录的意义：fileId 在上传前就确定，客户端上传完直接用它注册，
// 不需要二次协商；同时孤儿 pending 记录可被清理任务回收。
func (s *Service) Presign(ctx context.Context, namespace, filename, contentType string, size int64, createdBy string) (*PresignResult, error) {
	prefix, err := s.cfg.ResolveNamespace(namespace)
	if err != nil {
		return nil, err
	}
	if filename = strings.TrimSpace(filename); filename == "" {
		return nil, fmt.Errorf("filename 不能为空")
	}
	if size > s.cfg.MaxSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooLarge, size, s.cfg.MaxSize)
	}

	fileID := uuid.NewString()
	objectKey, err := buildObjectKey(fileID, filename)
	if err != nil {
		return nil, err
	}

	if contentType == "" {
		contentType = guessContentType(filename)
	}

	cred, err := s.prv.PresignUpload(ctx, prefix, objectKey, contentType, size)
	if err != nil {
		return nil, fmt.Errorf("生成上传凭证失败: %w", err)
	}

	db, err := s.db()
	if err != nil {
		return nil, err
	}
	rec := &File{
		FileID:    fileID,
		Namespace: namespace,
		ObjectKey: objectKey,
		StoredURL: cred.StoredURL, // 引用型后端此处为空，注册时回填
		OrigName:  filename,
		Size:      size,
		MimeType:  contentType,
		CreatedBy: createdBy,
		Status:    StatusPending,
	}
	if err := db.WithContext(ctx).Create(rec).Error; err != nil {
		return nil, fmt.Errorf("写入文件元数据失败: %w", err)
	}

	return &PresignResult{FileID: fileID, ObjectKey: objectKey, Credential: cred}, nil
}

// RegisterInput 上传完成后的注册参数。
type RegisterInput struct {
	FileID string
	// StoredURL 存储地址。引用型后端可留空，改用 RefID。
	StoredURL string
	// RefID 存储后端返回的引用 ID。
	//
	// 部分后端上传完成前拿不到持久地址，客户端把后端返回的引用 ID 回传，
	// 服务端经 Provider 转成入库地址（见 provider.RefMaker）。
	// 与 StoredURL 二选一，RefID 优先。
	RefID string
	Name     string
	Size     int64
	MimeType string
	SHA256   string
}

// resolveStoredURL 决定本次注册最终要写入的存储 地址。
//
// 优先级：RefID（引用型后端的正路）> 客户端回传的 StoredURL > presign 时预置的值。
// 返回空串表示三者皆无 —— 调用方必须据此拒绝注册。
func resolveStoredURL(prv provider.Provider, in RegisterInput, existing string) string {
	if id := strings.TrimSpace(in.RefID); id != "" {
		if rm, ok := prv.(provider.RefMaker); ok {
			return rm.MakeRefURL(id)
		}
	}
	if s := strings.TrimSpace(in.StoredURL); s != "" {
		// 客户端可能回传一条**签名的**下载 URL；它带过期 token，
		// 直接入库会导致文件几小时后永久 403，须由后端收敛回 durable 形态。
		if nz, ok := prv.(provider.StoredURLNormalizer); ok {
			return nz.NormalizeStoredURL(s)
		}
		return s
	}
	return existing
}

// Register 上传完成回调：补齐元数据并置为 active。
//
// 幂等：重复注册同一 fileId 会覆盖元数据并保持 active，不报错。
func (s *Service) Register(ctx context.Context, namespace string, in RegisterInput) (*File, error) {
	if _, err := s.cfg.ResolveNamespace(namespace); err != nil {
		return nil, err
	}
	if in.Size > s.cfg.MaxSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooLarge, in.Size, s.cfg.MaxSize)
	}

	db, err := s.db()
	if err != nil {
		return nil, err
	}

	var rec File
	err = db.WithContext(ctx).Where("file_id = ?", in.FileID).First(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询文件元数据失败: %w", err)
	}
	// 命名空间必须与 presign 时一致，防止 A 服务注册 B 服务的 fileId。
	if rec.Namespace != namespace {
		return nil, ErrForbidden
	}

	// 先定地址再写库：地址缺失时必须在置为 active **之前**失败，
	// 否则会留下一条 active 但无 stored_url 的记录 —— 它能通过 Get，
	// 却在下载时才炸，且没有任何路径能把它修回来。
	storedURL := resolveStoredURL(s.prv, in, rec.StoredURL)
	if storedURL == "" {
		return nil, fmt.Errorf("storedUrl 不能为空（引用型后端需回传 refId）")
	}

	updates := map[string]interface{}{
		"status":     StatusActive,
		"stored_url": storedURL,
		"updated_at": time.Now(),
	}
	if in.Name != "" {
		updates["orig_name"] = in.Name
	}
	if in.Size > 0 {
		updates["size"] = in.Size
	}
	if in.MimeType != "" {
		updates["mime_type"] = in.MimeType
	}
	if in.SHA256 != "" {
		updates["sha256"] = in.SHA256
	}

	if err := db.WithContext(ctx).Model(&rec).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新文件元数据失败: %w", err)
	}

	return s.Get(ctx, namespace, in.FileID)
}

// Get 按 fileId 查询元数据，并校验命名空间归属。
func (s *Service) Get(ctx context.Context, namespace, fileID string) (*File, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	var rec File
	err = db.WithContext(ctx).Where("file_id = ?", fileID).First(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询文件元数据失败: %w", err)
	}
	if namespace != "" && rec.Namespace != namespace {
		return nil, ErrForbidden
	}
	return &rec, nil
}

// DownloadResult 下载签名结果。
type DownloadResult struct {
	URL       string `json:"url"`
	ExpiresIn int    `json:"expiresIn"`
	Name      string `json:"name"`
	MimeType  string `json:"mimeType"`
	Size      int64  `json:"size"`
}

// PresignDownload 生成签名下载 URL，客户端凭此直连后端/CDN。
func (s *Service) PresignDownload(ctx context.Context, namespace, fileID string) (*DownloadResult, error) {
	rec, err := s.Get(ctx, namespace, fileID)
	if err != nil {
		return nil, err
	}
	if rec.Status != StatusActive {
		return nil, fmt.Errorf("文件尚未完成上传（status=%s）", rec.Status)
	}
	url, err := s.prv.PresignDownload(ctx, rec.StoredURL)
	if err != nil {
		return nil, fmt.Errorf("生成下载链接失败: %w", err)
	}
	return &DownloadResult{
		URL:       url,
		ExpiresIn: s.expiresIn(),
		Name:      rec.OrigName,
		MimeType:  rec.MimeType,
		Size:      rec.Size,
	}, nil
}

// Delete 删除文件：先删后端字节，再软删元数据。
//
// 后端不支持删除时只做软删除，不视为失败（见 provider.ErrNotSupported）。
func (s *Service) Delete(ctx context.Context, namespace, fileID string) error {
	rec, err := s.Get(ctx, namespace, fileID)
	if err != nil {
		return err
	}

	if rec.StoredURL != "" {
		if err := s.prv.Delete(ctx, rec.StoredURL); err != nil && !errors.Is(err, provider.ErrNotSupported) {
			return fmt.Errorf("删除后端文件失败: %w", err)
		}
	}

	db, err := s.db()
	if err != nil {
		return err
	}
	if err := db.WithContext(ctx).Delete(rec).Error; err != nil {
		return fmt.Errorf("删除文件元数据失败: %w", err)
	}
	return nil
}

// expiresIn 返回当前 Provider 的签名有效期（秒）。
//
// local 用配置值；插件后端无统一接口，返回通用默认值（签名 URL 本就带过期时间，客户端可容忍）。
func (s *Service) expiresIn() int {
	if s.cfg.Provider == "local" {
		return s.cfg.Local.GetExpires()
	}
	return config.DefaultExpires
}

// buildObjectKey 生成对象相对路径：{yyyy}/{mm}/{fileId}/{filename}。
//
// fileId 单独占一层目录，原始文件名作为叶子节点。这样：
//   - 同名文件天然隔离（各自在自己的 fileId 目录下），不会互相覆盖
//   - 下载时 URL 末段就是真实文件名，浏览器/CDN 能给出正确的保存名与 Content-Type
//   - 按 {yyyy}/{mm} 分片，避免单目录下对象数量爆炸
//
// 文件名会被清洗（见 sanitizeFileName）：CS 的 path 是签名 policy 的一部分，
// 未清洗的文件名可能撑爆长度限制或注入路径分隔符。
func buildObjectKey(fileID, filename string) (string, error) {
	name := sanitizeFileName(filename)
	now := time.Now().UTC()
	key := fmt.Sprintf("%04d/%02d/%s/%s", now.Year(), int(now.Month()), fileID, name)
	return provider.SanitizeKey(key)
}

// maxStoredFileNameLen 存储路径中文件名的最大字节数。
//
// CS 的 policy 里带完整 path，整条路径过长会被服务端拒绝；
// 这里给文件名留一个保守上限，超出则截断主干、保留扩展名。
const maxStoredFileNameLen = 96

// sanitizeFileName 把用户提供的文件名清洗成可安全放进存储路径的形态。
//
// 处理项：
//   - 只取 basename，丢掉任何目录成分（防 ../ 与绝对路径）
//   - 剔除路径分隔符、控制字符与对 URL/签名有歧义的字符
//   - 超长时截断主干但保留扩展名（扩展名决定 Content-Type，不能丢）
//   - 清洗后为空则兜底为 "file"，保证路径始终有合法叶子节点
func sanitizeFileName(filename string) string {
	base := path.Base(strings.ReplaceAll(filename, "\\", "/"))
	base = strings.TrimSpace(base)

	// 全是 . 或 .. 的畸形输入，直接兜底。
	if base == "" || base == "." || base == ".." {
		return "file"
	}

	cleaned := strings.Map(func(r rune) rune {
		// 控制字符与空白一律替换为下划线，避免 URL 里出现裸空格/换行。
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		switch r {
		case '/', '\\', '?', '#', '%', '"', '\'', '<', '>', '|', ':', '*':
			return '_'
		case ' ':
			return '_'
		}
		return r
	}, base)

	// 先去掉前导点再取扩展名。否则点文件会被误判：
	// path.Ext(".gitignore") 返回的是 ".gitignore" 整体（Go 的定义），
	// 直接 TrimSuffix 会把主干清空，得到 "file.gitignore" 这种荒唐结果。
	cleaned = strings.TrimLeft(cleaned, ".")
	if cleaned == "" {
		return "file"
	}

	ext := path.Ext(cleaned)
	// 畸形/超长扩展名不予保留，避免它吃掉整个长度预算。
	if len(ext) > 16 {
		ext = ""
	}
	stem := strings.TrimSuffix(cleaned, ext)
	stem = strings.Trim(stem, ".")
	if stem == "" {
		stem = "file"
	}

	// 截断按字节算，但不能把多字节字符（中文名很常见）切成半个。
	if limit := maxStoredFileNameLen - len(ext); len(stem) > limit {
		stem = truncateUTF8(stem, limit)
		if stem == "" {
			stem = "file"
		}
	}
	return stem + ext
}

// truncateUTF8 按字节上限截断字符串，且不切断多字节字符。
func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	// 从 limit 处向前回退到一个合法的 rune 边界。
	for i := limit; i > 0; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i]
		}
	}
	return ""
}

// guessContentType 按扩展名猜 MIME，猜不到用通用二进制类型。
func guessContentType(filename string) string {
	if ct := mime.TypeByExtension(path.Ext(filename)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}
