package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/h1s97x/openidp/api/internal/middleware"
)

// ok writes the unified success envelope: {"data": v, "status": "ok"}.
func ok(w http.ResponseWriter, r *http.Request, v any) {
	writeJSON(w, http.StatusOK, map[string]any{"data": v, "status": "ok"})
}

// writeJSON writes arbitrary JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// apiError is the unified error envelope.
type apiError struct {
	Status    int               `json:"status"`
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	RequestID string            `json:"requestId"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// fail writes the unified error body:
//
//	{"status":<code>,"code":"<slug>","message":"<zh>","requestId":"<hex>"}
func fail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, apiError{
		Status:    status,
		Code:      code,
		Message:   message,
		RequestID: middleware.RequestID(r.Context()),
	})
}

// decodeJSON 解析请求体到 v，失败时写出统一的 400 错误 envelope。
// 返回 true 表示解析成功，调用方可直接使用 v。
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		fail(w, r, http.StatusBadRequest, "request.invalid_body", "请求体格式错误")
		return false
	}
	return true
}

// decodeJSONBody 解析请求体到 v，静默忽略错误。
// 用于「可选参数」解析：解析失败时保持 v 的零值，由调用方按需回退。
func decodeJSONBody(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}
