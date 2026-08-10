package blob

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"whitestone.top/prism-fusion/global"

	"nucleagent-storage/provider"
)

// newHandler 构造 /blob 处理器。
//
// PUT  /blob/{path}?expires&max&sig  上传（写文件）
// GET  /blob/{path}?expires&max&sig  下载（读文件）
//
// 鉴权完全依赖 URL 签名（HMAC-SHA256），不看 JWT —— 这正是 presign 模式的意义：
// 凭证一次性签发，客户端直连，存储后端无需理解业务身份。
func newHandler(lp *provider.LocalProvider, maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqPath := c.Request.URL.Path
		if !strings.HasPrefix(reqPath, provider.BlobPath+"/") {
			c.Next()
			return
		}

		method := c.Request.Method
		if method != http.MethodPut && method != http.MethodGet && method != http.MethodHead {
			abort(c, http.StatusMethodNotAllowed, "不支持的方法")
			return
		}

		// 还原签名时使用的逻辑路径（未转义形态）。
		// 用 EscapedPath 再解码，避免 gin 已解码路径导致含 %2F 的名字对不上。
		full, err := url.PathUnescape(strings.TrimPrefix(c.Request.URL.EscapedPath(), provider.BlobPath))
		if err != nil || full == "" || full == "/" {
			abort(c, http.StatusBadRequest, "非法的对象路径")
			return
		}

		expires, err := strconv.ParseInt(c.Query("expires"), 10, 64)
		if err != nil {
			abort(c, http.StatusBadRequest, "缺少或非法的 expires 参数")
			return
		}
		declaredMax, err := strconv.ParseInt(c.Query("max"), 10, 64)
		if err != nil {
			abort(c, http.StatusBadRequest, "缺少或非法的 max 参数")
			return
		}

		// 签名方法与实际方法绑定；HEAD 复用 GET 的签名。
		signMethod := method
		if method == http.MethodHead {
			signMethod = http.MethodGet
		}
		if err := lp.Verify(signMethod, full, expires, declaredMax, c.Query("sig")); err != nil {
			global.PRISM_LOG.Warn("blob: 签名校验未通过",
				zap.String("path", full), zap.String("method", method), zap.Error(err))
			abort(c, http.StatusForbidden, err.Error())
			return
		}

		abs, err := lp.ResolvePath(full)
		if err != nil {
			abort(c, http.StatusBadRequest, err.Error())
			return
		}

		if method == http.MethodPut {
			handleUpload(c, abs, declaredMax, maxSize)
			return
		}
		handleDownload(c, abs)
	}
}

// handleUpload 把请求体写入磁盘。
//
// 双重限额：presign 时声明的 declaredMax 与全局 maxSize 取小者，
// 用 io.LimitReader + 溢出探测强制执行，不信任 Content-Length。
func handleUpload(c *gin.Context, abs string, declaredMax, maxSize int64) {
	limit := maxSize
	if declaredMax > 0 && declaredMax < limit {
		limit = declaredMax
	}

	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		fail(c, "创建目录失败", err)
		return
	}

	// 先写临时文件再 rename：避免写到一半失败留下半截文件被当成完整对象。
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".upload-*")
	if err != nil {
		fail(c, "创建临时文件失败", err)
		return
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // rename 成功后这里是 no-op
	}()

	// 多读 1 字节用于探测是否超限。
	written, err := io.Copy(tmp, io.LimitReader(c.Request.Body, limit+1))
	if err != nil {
		fail(c, "写入文件失败", err)
		return
	}
	if written > limit {
		abort(c, http.StatusRequestEntityTooLarge, "文件超过大小上限")
		return
	}
	if err := tmp.Close(); err != nil {
		fail(c, "关闭临时文件失败", err)
		return
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		fail(c, "设置文件权限失败", err)
		return
	}
	if err := os.Rename(tmpName, abs); err != nil {
		fail(c, "提交文件失败", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    gin.H{"size": written},
	})
	c.Abort()
}

// handleDownload 直接把文件发给客户端。
//
// 用 http.ServeFile 以获得 Range / If-Modified-Since / Content-Type 支持。
func handleDownload(c *gin.Context, abs string) {
	st, err := os.Stat(abs)
	if err != nil || st.IsDir() {
		abort(c, http.StatusNotFound, "文件不存在")
		return
	}
	http.ServeFile(c.Writer, c.Request, abs)
	c.Abort()
}

// abort 以 {code,message} 信封中断请求。
func abort(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"code": status, "message": msg})
}

// fail 记录内部错误并返回 500（不把细节透给调用方）。
func fail(c *gin.Context, msg string, err error) {
	global.PRISM_LOG.Error("blob: "+msg, zap.Error(err))
	abort(c, http.StatusInternalServerError, msg)
}
