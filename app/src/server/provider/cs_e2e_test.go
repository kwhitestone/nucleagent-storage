package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"nucleagent-storage/internal/config"
)

// fakeCS 是一个最小的 CS 服务端仿真：按 CS 的规则**独立重算签名**并校验。
//
// 它证明的不是「我们的签名等于我们的签名」，而是「客户端拿着我们签发的凭证，
// 按 CS 协议发出的请求，能被一个独立实现的校验方接受」—— 即凭证真的可用。
func fakeCS(t *testing.T, secret string, received *[]byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v0.1/upload", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		token, date, policyB64 := q.Get("token"), q.Get("date"), q.Get("policy")

		// token 必须是 serverName:accessKey:sign 三段。
		parts := strings.Split(token, ":")
		if len(parts) != 3 {
			http.Error(w, "malformed token", http.StatusBadRequest)
			return
		}
		gotSign := parts[2]

		// 服务端从 base64 policy 还原出 JSON 原文，用它重算签名。
		policyBytes, err := base64.RawURLEncoding.DecodeString(policyB64)
		if err != nil {
			http.Error(w, "bad policy encoding", http.StatusBadRequest)
			return
		}

		// 按 CS 协议重算：HMAC-SHA1("{date}\n{path}\n{method}\n{policy}")
		signSource := fmt.Sprintf("%s\n%s\n%s\n%s", date, "/v0.1/upload", "POST", string(policyBytes))
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write([]byte(signSource))
		wantSign := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(gotSign), []byte(wantSign)) {
			http.Error(w, "signature mismatch", http.StatusForbidden)
			return
		}

		// policy 内容必须自洽（含 path/uid/policyType/scope）。
		var policy map[string]interface{}
		if err := json.Unmarshal(policyBytes, &policy); err != nil {
			http.Error(w, "bad policy json", http.StatusBadRequest)
			return
		}
		if policy["policyType"] != "upload" {
			http.Error(w, "wrong policyType", http.StatusForbidden)
			return
		}
		// uid 必须是 JSON 数字（反序列化后为 float64），不能是字符串。
		if _, ok := policy["uid"].(float64); !ok {
			http.Error(w, "uid must be a number", http.StatusBadRequest)
			return
		}

		// 读取 multipart 表单，确认表单字段与文件字段名正确。
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, "bad multipart", http.StatusBadRequest)
			return
		}
		// 表单里的 path+name 必须与 policy 里签名的 path 一致，
		// 否则客户端可以拿 A 的签名往 B 的位置写。
		formPath := r.FormValue("path") + "/" + r.FormValue("name")
		if formPath != policy["path"] {
			http.Error(w, "form path does not match signed policy", http.StatusForbidden)
			return
		}

		f, hdr, err := r.FormFile("filename")
		if err != nil {
			http.Error(w, "missing file field 'filename'", http.StatusBadRequest)
			return
		}
		defer f.Close()
		data, _ := io.ReadAll(f)
		*received = data

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"path":      policy["path"],
			"name":      hdr.Filename,
			"size":      len(data),
			"dentry_id": "fake-dentry-001",
		})
	})

	mux.HandleFunc("/v0.1/download", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		dentryID, token, policyB64, expireAt := q.Get("dentryId"), q.Get("token"), q.Get("policy"), q.Get("expireAt")

		parts := strings.Split(token, ":")
		if len(parts) != 3 {
			http.Error(w, "malformed token", http.StatusBadRequest)
			return
		}
		policyBytes, err := base64.RawURLEncoding.DecodeString(policyB64)
		if err != nil {
			http.Error(w, "bad policy encoding", http.StatusBadRequest)
			return
		}

		// 下载签名串：首段是 expireAt，路径带 dentryId 查询串。
		signSource := fmt.Sprintf("%s\n%s\n%s\n%s",
			expireAt, "/v0.1/download?dentryId="+dentryID, "GET", string(policyBytes))
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write([]byte(signSource))
		wantSign := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(parts[2]), []byte(wantSign)) {
			http.Error(w, "signature mismatch", http.StatusForbidden)
			return
		}
		w.Write(*received)
	})

	return httptest.NewServer(mux)
}

// TestCSProvider_EndToEndAgainstFakeCS 用仿真 CS 跑通完整链路：
// presign → 客户端直传 → 注册 dentryId → 签名下载 → 字节比对。
//
// 这验证的是「凭证可被独立实现的 CS 校验方接受」，而非自证。
func TestCSProvider_EndToEndAgainstFakeCS(t *testing.T) {
	var stored []byte
	secret := "sk_e2e_secret"
	srv := fakeCS(t, secret, &stored)
	defer srv.Close()

	cfg := &config.CS{
		Host:       srv.URL + "/v0.1",
		CDNHost:    srv.URL + "/v0.1",
		ServerName: "test_server",
		AccessKey:  "ak_e2e",
		SecretKey:  secret,
		UserID:     "100000101",
		Scope:      0, // 私有：下载必须签名
		Expires:    1800,
	}
	p := NewCSProvider(cfg)
	ctx := context.Background()
	payload := []byte("nucleagent storage CS 直传测试\n中文内容\x00\x01二进制")

	// --- 1) presign ---
	cred, err := p.PresignUpload(ctx, "/nucleagent/core/", "2026/08/e2e.bin", "application/octet-stream", int64(len(payload)))
	if err != nil {
		t.Fatalf("PresignUpload 失败: %v", err)
	}
	if cred.StoredURL != "" {
		t.Errorf("私有文件 presign 阶段 storedUrl 应为空，实际 %s", cred.StoredURL)
	}

	// --- 2) 客户端按凭证直传（完全模拟客户端行为）---

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		defer pw.Close()
		for k, v := range cred.FormFields {
			_ = mw.WriteField(k, v)
		}
		part, err := mw.CreateFormFile(cred.FileField, "e2e.bin")
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		part.Write(payload)
		mw.Close()
	}()

	req, err := http.NewRequest(cred.Method, cred.URL, pr)
	if err != nil {
		t.Fatalf("构造上传请求失败: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("上传请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("仿真 CS 拒绝了我们签发的上传凭证: HTTP %d, %s", resp.StatusCode, respBody)
	}

	var upResp struct {
		DentryID string `json:"dentry_id"`
		Size     int    `json:"size"`
	}
	if err := json.Unmarshal(respBody, &upResp); err != nil {
		t.Fatalf("解析上传响应失败: %v", err)
	}
	if upResp.Size != len(payload) {
		t.Errorf("CS 收到的字节数不符: got %d, want %d", upResp.Size, len(payload))
	}

	// --- 3) 用 CS 返回的 dentryId 生成签名下载 URL ---
	dlURL, err := p.PresignDownload(ctx, MakeDentryURL(upResp.DentryID))
	if err != nil {
		t.Fatalf("PresignDownload 失败: %v", err)
	}

	// --- 4) 客户端直连下载并比对字节 ---
	dlResp, err := http.Get(dlURL)
	if err != nil {
		t.Fatalf("下载请求失败: %v", err)
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(dlResp.Body)
		t.Fatalf("仿真 CS 拒绝了我们签发的下载凭证: HTTP %d, %s", dlResp.StatusCode, b)
	}
	got, _ := io.ReadAll(dlResp.Body)
	if string(got) != string(payload) {
		t.Errorf("下载内容与上传不一致\n got: %q\nwant: %q", got, payload)
	}
}

// TestCSProvider_TamperedTokenRejectedByCS 篡改后的凭证必须被 CS 拒绝。
//
// 反向验证：确认上面的成功不是因为仿真 CS 校验太松。
func TestCSProvider_TamperedTokenRejectedByCS(t *testing.T) {
	var stored []byte
	secret := "sk_e2e_secret"
	srv := fakeCS(t, secret, &stored)
	defer srv.Close()

	p := NewCSProvider(&config.CS{
		Host: srv.URL + "/v0.1", CDNHost: srv.URL + "/v0.1",
		ServerName: "test_server", AccessKey: "ak", SecretKey: secret,
		UserID: "100000101", Scope: 0, Expires: 1800,
	})

	cred, err := p.PresignUpload(context.Background(), "/nucleagent/core/", "a.bin", "", 4)
	if err != nil {
		t.Fatalf("PresignUpload 失败: %v", err)
	}

	// 篡改 policy 里签名的路径（想写到别的位置），签名不变。
	u, _ := url.Parse(cred.URL)
	q := u.Query()
	evil, _ := json.Marshal(map[string]interface{}{
		"path": "/test_server/nucleagent/executor/pwned.bin", "uid": 100000101,
		"role": "admin", "policyType": "upload", "scope": 0,
	})
	q.Set("policy", base64.RawURLEncoding.EncodeToString(evil))
	u.RawQuery = q.Encode()

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		defer pw.Close()
		_ = mw.WriteField("path", "/test_server/nucleagent/executor")
		_ = mw.WriteField("name", "pwned.bin")
		_ = mw.WriteField("scope", "0")
		part, _ := mw.CreateFormFile("filename", "pwned.bin")
		part.Write([]byte("evil"))
		mw.Close()
	}()

	req, _ := http.NewRequest("POST", u.String(), pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Error("篡改 policy 的上传应被 CS 拒绝，却成功了")
	}
}
