// Package router 文件元数据 HTTP 路由（huma 注册，OpenAPI 自动生成）。
//
// 所有端点都只处理元数据与签名，**不接收也不返回文件字节流**。
// 字节流走 LocalProvider 的 /blob 端点或 CS/CDN，客户端直连。
package router

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/zap"
	"github.com/kwhitestone/prism-fusion/global"

	"github.com/kwhitestone/nucleagent-storage/addons/file/svc"
)

// fileSvc 由 plugin 在注册路由前注入。
var fileSvc *svc.Service

// RegisterRoutes 注册文件相关路由。
func RegisterRoutes(api huma.API, s *svc.Service) {
	fileSvc = s
	registerPresignUpload(api)
	registerCreateFile(api)
	registerGetFile(api)
	registerDownload(api)
	registerDeleteFile(api)
	registerHealth(api)
}

// ===== 通用信封 =====

// 沿用 nucleagent 的 {code, message, data} 数字信封。
// huma 用结构体名生成 schema，名字必须全局唯一。

// PresignUploadData presign 响应数据。
type PresignUploadData struct {
	FileID     string            `json:"fileId" doc:"文件ID，上传完成后用它注册元数据"`
	ObjectKey  string            `json:"objectKey" doc:"命名空间内的对象路径"`
	Method     string            `json:"method" doc:"上传使用的 HTTP 方法"`
	UploadURL  string            `json:"uploadUrl" doc:"上传目标地址（已含签名）"`
	Headers    map[string]string `json:"headers,omitempty" doc:"上传需携带的请求头"`
	FormFields map[string]string `json:"formFields,omitempty" doc:"multipart 表单字段（CS 后端必填）"`
	FileField  string            `json:"fileField,omitempty" doc:"文件内容的 multipart 字段名"`
	StoredURL  string            `json:"storedUrl,omitempty" doc:"预知的存储地址；CS 私有文件为空，需上传后回填"`
	ExpiresAt  int64             `json:"expiresAt" doc:"凭证过期时间（Unix 毫秒）"`
}

// PresignUploadBody presign 响应信封。
type PresignUploadBody struct {
	Code    int                `json:"code" example:"0"`
	Message string             `json:"message" example:"success"`
	Data    *PresignUploadData `json:"data"`
}

// FileBody 单文件元数据响应信封。
type FileBody struct {
	Code    int       `json:"code" example:"0"`
	Message string    `json:"message" example:"success"`
	Data    *svc.File `json:"data"`
}

// DownloadBody 下载签名响应信封。
type DownloadBody struct {
	Code    int                 `json:"code" example:"0"`
	Message string              `json:"message" example:"success"`
	Data    *svc.DownloadResult `json:"data"`
}

// PlainBody 无数据体的响应信封。
type PlainBody struct {
	Code    int    `json:"code" example:"0"`
	Message string `json:"message" example:"success"`
}

// HealthData 健康检查数据。
type HealthData struct {
	Status   string `json:"status" example:"healthy"`
	Provider string `json:"provider" example:"local"`
	Database bool   `json:"database"`
}

// HealthBody 健康检查响应信封。
type HealthBody struct {
	Code    int        `json:"code" example:"0"`
	Message string     `json:"message" example:"success"`
	Data    HealthData `json:"data"`
}

// ===== 端点 =====

// PresignUploadInput 上传凭证请求。
//
// Namespace 走 X-Namespace 头而非 body：它是调用方身份的一部分，
// 便于网关/中间件统一校验，也和 body 里的业务参数分离。
type PresignUploadInput struct {
	Namespace string `header:"X-Namespace" required:"true" doc:"命名空间（core / executor）"`
	Body      struct {
		Filename    string `json:"filename" required:"true" minLength:"1" doc:"原始文件名"`
		ContentType string `json:"contentType,omitempty" doc:"MIME 类型，留空按扩展名推断"`
		Size        int64  `json:"size,omitempty" minimum:"0" doc:"文件字节数"`
	}
}

// PresignUploadOutput 上传凭证响应。
type PresignUploadOutput struct {
	Body PresignUploadBody
}

func registerPresignUpload(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "storagePresignUpload",
		Method:      http.MethodPost,
		Path:        "/api/v1/upload/presign",
		Summary:     "生成上传凭证",
		Description: "返回客户端直传存储后端所需的 URL 与签名，服务端不代理字节流",
		Tags:        []string{"Storage"},
		Security:    []map[string][]string{{"AuthTokenAuth": {}}},
	}, func(ctx context.Context, in *PresignUploadInput) (*PresignUploadOutput, error) {
		res, err := fileSvc.Presign(ctx, in.Namespace, in.Body.Filename, in.Body.ContentType, in.Body.Size, callerFromCtx(ctx))
		if err != nil {
			return nil, mapErr(err, "生成上传凭证失败")
		}
		out := &PresignUploadOutput{}
		out.Body.Code = 0
		out.Body.Message = "success"
		out.Body.Data = &PresignUploadData{
			FileID:     res.FileID,
			ObjectKey:  res.ObjectKey,
			Method:     res.Credential.Method,
			UploadURL:  res.Credential.URL,
			Headers:    res.Credential.Headers,
			FormFields: res.Credential.FormFields,
			FileField:  res.Credential.FileField,
			StoredURL:  res.Credential.StoredURL,
			ExpiresAt:  res.Credential.ExpiresAt,
		}
		return out, nil
	})
}

// CreateFileInput 上传完成后的元数据注册请求。
type CreateFileInput struct {
	Namespace string `header:"X-Namespace" required:"true" doc:"命名空间（core / executor）"`
	Body      struct {
		FileID    string `json:"fileId" required:"true" minLength:"1" doc:"presign 返回的文件ID"`
		DentryID  string `json:"dentryId,omitempty" doc:"CS 上传响应里的 dentry_id；CS 私有文件用它回填存储地址"`
		StoredURL string `json:"storedUrl,omitempty" doc:"存储地址；与 dentryId 二选一，dentryId 优先"`
		Name      string `json:"name,omitempty" doc:"原始文件名"`
		Size      int64  `json:"size,omitempty" minimum:"0" doc:"文件字节数"`
		MimeType  string `json:"mimeType,omitempty" doc:"MIME 类型"`
		SHA256    string `json:"sha256,omitempty" doc:"内容 SHA256"`
	}
}

// CreateFileOutput 注册响应。
type CreateFileOutput struct {
	Body FileBody
}

func registerCreateFile(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "storageCreateFile",
		Method:        http.MethodPost,
		Path:          "/api/v1/files",
		Summary:       "注册文件元数据",
		Description:   "客户端上传完成后回调，补齐存储地址等元数据并置为 active",
		Tags:          []string{"Storage"},
		DefaultStatus: http.StatusCreated,
		Security:      []map[string][]string{{"AuthTokenAuth": {}}},
	}, func(ctx context.Context, in *CreateFileInput) (*CreateFileOutput, error) {
		rec, err := fileSvc.Register(ctx, in.Namespace, svc.RegisterInput{
			FileID:    in.Body.FileID,
			DentryID:  in.Body.DentryID,
			StoredURL: in.Body.StoredURL,
			Name:      in.Body.Name,
			Size:      in.Body.Size,
			MimeType:  in.Body.MimeType,
			SHA256:    in.Body.SHA256,
		})
		if err != nil {
			return nil, mapErr(err, "注册文件元数据失败")
		}
		out := &CreateFileOutput{}
		out.Body.Code = 0
		out.Body.Message = "success"
		out.Body.Data = rec
		return out, nil
	})
}

// GetFileInput 查询元数据请求。
type GetFileInput struct {
	Namespace string `header:"X-Namespace" required:"true" doc:"命名空间（core / executor）"`
	ID        string `path:"id" doc:"文件ID"`
}

// GetFileOutput 查询元数据响应。
type GetFileOutput struct {
	Body FileBody
}

func registerGetFile(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "storageGetFile",
		Method:      http.MethodGet,
		Path:        "/api/v1/files/{id}",
		Summary:     "获取文件元数据",
		Tags:        []string{"Storage"},
		Security:    []map[string][]string{{"AuthTokenAuth": {}}},
	}, func(ctx context.Context, in *GetFileInput) (*GetFileOutput, error) {
		rec, err := fileSvc.Get(ctx, in.Namespace, in.ID)
		if err != nil {
			return nil, mapErr(err, "查询文件元数据失败")
		}
		out := &GetFileOutput{}
		out.Body.Code = 0
		out.Body.Message = "success"
		out.Body.Data = rec
		return out, nil
	})
}

// DownloadInput 下载签名请求。
//
// redirect=true 时返回 302 跳转到签名 URL（浏览器 <a href> 直接可用）；
// 默认返回 JSON，便于程序化调用拿到 URL 后自行处理。
type DownloadInput struct {
	Namespace string `header:"X-Namespace" required:"true" doc:"命名空间（core / executor）"`
	ID        string `path:"id" doc:"文件ID"`
	Redirect  bool   `query:"redirect" doc:"true 则 302 跳转到签名地址，默认返回 JSON"`
}

// DownloadOutput 下载签名响应。
//
// Location 非空时 huma 会写出 302 响应头。
type DownloadOutput struct {
	Status   int
	Location string `header:"Location"`
	Body     DownloadBody
}

func registerDownload(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "storageDownloadFile",
		Method:      http.MethodGet,
		Path:        "/api/v1/files/{id}/download",
		Summary:     "生成签名下载地址",
		Description: "返回客户端可直连 CDN/后端的签名 URL；服务端不代理字节流",
		Tags:        []string{"Storage"},
		Security:    []map[string][]string{{"AuthTokenAuth": {}}},
	}, func(ctx context.Context, in *DownloadInput) (*DownloadOutput, error) {
		res, err := fileSvc.PresignDownload(ctx, in.Namespace, in.ID)
		if err != nil {
			return nil, mapErr(err, "生成下载地址失败")
		}
		out := &DownloadOutput{Status: http.StatusOK}
		out.Body.Code = 0
		out.Body.Message = "success"
		out.Body.Data = res
		if in.Redirect {
			out.Status = http.StatusFound
			out.Location = res.URL
		}
		return out, nil
	})
}

// DeleteFileInput 删除请求。
type DeleteFileInput struct {
	Namespace string `header:"X-Namespace" required:"true" doc:"命名空间（core / executor）"`
	ID        string `path:"id" doc:"文件ID"`
}

// DeleteFileOutput 删除响应。
type DeleteFileOutput struct {
	Body PlainBody
}

func registerDeleteFile(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "storageDeleteFile",
		Method:      http.MethodDelete,
		Path:        "/api/v1/files/{id}",
		Summary:     "删除文件",
		Description: "软删除元数据；后端支持时同时删除字节（CS 不支持则仅软删）",
		Tags:        []string{"Storage"},
		Security:    []map[string][]string{{"AuthTokenAuth": {}}},
	}, func(ctx context.Context, in *DeleteFileInput) (*DeleteFileOutput, error) {
		if err := fileSvc.Delete(ctx, in.Namespace, in.ID); err != nil {
			return nil, mapErr(err, "删除文件失败")
		}
		out := &DeleteFileOutput{}
		out.Body.Code = 0
		out.Body.Message = "删除成功"
		return out, nil
	})
}

// HealthOutput 健康检查响应。
type HealthOutput struct {
	Body HealthBody
}

func registerHealth(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "storageHealth",
		Method:      http.MethodGet,
		Path:        "/api/v1/health",
		Summary:     "健康检查",
		Tags:        []string{"Storage"},
	}, func(_ context.Context, _ *struct{}) (*HealthOutput, error) {
		out := &HealthOutput{}
		out.Body.Code = 0
		out.Body.Message = "success"
		out.Body.Data = HealthData{
			Status:   "healthy",
			Provider: fileSvc.Provider().Name(),
			Database: global.PRISM_DB != nil,
		}
		return out, nil
	})
}

// ===== 辅助 =====

// mapErr 把业务错误映射到 HTTP 状态码。
//
// 未识别的错误统一 500 并记日志 —— 不把内部细节透给调用方。
func mapErr(err error, fallback string) error {
	switch {
	case errors.Is(err, svc.ErrNotFound):
		return huma.NewError(http.StatusNotFound, "文件不存在")
	case errors.Is(err, svc.ErrForbidden):
		return huma.NewError(http.StatusForbidden, "无权访问该文件")
	case errors.Is(err, svc.ErrTooLarge):
		return huma.NewError(http.StatusRequestEntityTooLarge, err.Error())
	}
	global.PRISM_LOG.Error("storage: "+fallback, zap.Error(err))
	return huma.NewError(http.StatusBadRequest, err.Error())
}
