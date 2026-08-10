package svc

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"whitestone.top/prism-fusion/global"

	"nucleagent-storage/internal/config"
	"nucleagent-storage/provider"
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
		StoredURL: cred.StoredURL, // CS 私有文件此处为空，注册时回填
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
	FileID    string
	StoredURL string
	Name      string
	Size      int64
	MimeType  string
	SHA256    string
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

	updates := map[string]interface{}{
		"status":     StatusActive,
		"updated_at": time.Now(),
	}
	if in.StoredURL != "" {
		updates["stored_url"] = in.StoredURL
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

	// storedURL 仍为空说明客户端没回传（CS 私有文件必须回传 dentryId）。
	if rec.StoredURL == "" && in.StoredURL == "" {
		return nil, fmt.Errorf("storedUrl 不能为空（CS 私有文件需回传 cs-dentry://{dentryId}）")
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
// 后端不支持删除（如 CS）时只做软删除，不视为失败。
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
func (s *Service) expiresIn() int {
	if s.cfg.Provider == "cs" {
		return s.cfg.CS.GetExpires()
	}
	return s.cfg.Local.GetExpires()
}

// buildObjectKey 生成对象相对路径：{yyyy}/{mm}/{fileId}{ext}。
//
// 用 fileId 而非原始文件名做主体，避免同名覆盖与文件名注入；
// 保留扩展名是为了 CDN 能正确推断 Content-Type。
func buildObjectKey(fileID, filename string) (string, error) {
	ext := path.Ext(path.Base(strings.ReplaceAll(filename, "\\", "/")))
	// 扩展名只保留合法字符，长度设上限，防止畸形输入进路径。
	if len(ext) > 16 || strings.ContainsAny(ext, "/\\ ?#") {
		ext = ""
	}
	now := time.Now().UTC()
	key := fmt.Sprintf("%04d/%02d/%s%s", now.Year(), int(now.Month()), fileID, ext)
	return provider.SanitizeKey(key)
}

// guessContentType 按扩展名猜 MIME，猜不到用通用二进制类型。
func guessContentType(filename string) string {
	if ct := mime.TypeByExtension(path.Ext(filename)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}
