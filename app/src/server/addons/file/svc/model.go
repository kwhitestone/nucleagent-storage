// Package svc 文件元数据领域服务：presign / 注册 / 查询 / 下载签名 / 删除。
package svc

import (
	"time"

	"gorm.io/gorm"
)

// File 文件元数据表。
//
// storage 服务只存元数据 —— 字节流永远在 StoredURL 指向的后端里，
// 本服务从不持有文件内容。
type File struct {
	ID        uint           `json:"id" gorm:"primarykey;comment:主键ID"`
	CreatedAt time.Time      `json:"createdAt" gorm:"column:created_at;comment:创建时间"`
	UpdatedAt time.Time      `json:"updatedAt" gorm:"column:updated_at;comment:更新时间"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index;comment:删除时间(软删除)"`

	// FileID 对外暴露的文件 ID（UUID），presign 阶段即生成。
	// 对外一律用它，不暴露自增主键。
	FileID string `json:"fileId" gorm:"column:file_id;size:64;uniqueIndex;comment:对外文件ID(UUID)"`
	// Namespace 命名空间（core / executor），隔离不同调用方。
	Namespace string `json:"namespace" gorm:"column:namespace;size:32;index;comment:命名空间"`
	// ObjectKey 命名空间内的对象相对路径（不含 prefix）。
	ObjectKey string `json:"objectKey" gorm:"column:object_key;size:512;comment:命名空间内对象路径"`
	// StoredURL 后端存储地址（后端自定义 scheme（如 ref://xxx）或 file:///nucleagent/core/xxx）。
	StoredURL string `json:"storedUrl" gorm:"column:stored_url;size:512;comment:后端存储地址"`
	// OrigName 上传时的原始文件名。
	OrigName string `json:"origName" gorm:"column:orig_name;size:256;comment:原始文件名"`
	// Size 文件字节数。
	Size int64 `json:"size" gorm:"column:size;comment:文件大小(字节)"`
	// MimeType 文件 MIME 类型。
	MimeType string `json:"mimeType" gorm:"column:mime_type;size:128;comment:MIME类型"`
	// SHA256 文件内容摘要（可选，由客户端上报）。
	SHA256 string `json:"sha256" gorm:"column:sha256;size:64;index;comment:内容SHA256"`
	// CreatedBy 创建者标识（JWT 的 user_id，S2S 场景为服务名）。
	CreatedBy string `json:"createdBy" gorm:"column:created_by;size:64;index;comment:创建者"`
	// Status 生命周期状态：pending=已签发凭证未确认上传，active=已注册可用。
	Status string `json:"status" gorm:"column:status;size:16;index;default:pending;comment:状态(pending/active)"`
}

// TableName 固定表名。
func (File) TableName() string { return "files" }

// 文件状态常量。
const (
	// StatusPending 已签发上传凭证，尚未确认上传完成。
	StatusPending = "pending"
	// StatusActive 已注册元数据，可下载。
	StatusActive = "active"
)
