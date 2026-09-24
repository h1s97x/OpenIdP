package handler

import (
	"context"
	"encoding/json"
	"time"
)

// consentKey 是 consent 请求参数在共享缓存中的键前缀。
const consentKey = "consentreq:"

// consentTTL 是 consent ticket 的有效期（与 HandleAuthorize 中 10 分钟校验一致）。
const consentTTL = 10 * time.Minute

// storeConsent 把一次待确认的 OIDC 授权请求参数写入共享缓存，绑定到 ticket。
func (h *Handler) storeConsent(ticket string, req consentReq) {
	b, _ := json.Marshal(req)
	h.cache.Set(context.Background(), consentKey+ticket, string(b), consentTTL)
}

// takeConsent 原子地取出并删除一个 consent ticket；返回 (参数, 是否找到)。
func (h *Handler) takeConsent(ticket string) (consentReq, bool) {
	var req consentReq
	raw, ok := h.cache.GetDel(context.Background(), consentKey+ticket)
	if !ok {
		return req, false
	}
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return consentReq{}, false
	}
	return req, true
}

// peekConsent 只读地查看一个 consent ticket 的参数（不消费）。
func (h *Handler) peekConsent(ticket string) (consentReq, bool) {
	var req consentReq
	raw, ok := h.cache.Get(context.Background(), consentKey+ticket)
	if !ok {
		return req, false
	}
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return consentReq{}, false
	}
	return req, true
}
