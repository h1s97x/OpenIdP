package handler

import (
	"net/url"
	"strings"
)

// sanitizeExternalURL 归一化「将会被渲染成链接」的外部地址。
//
// 背景：应用（OAuth client）的 Logo / 主页地址由管理员填写，前端会直接渲染进
// <img src> / <a href>。若只做 TrimSpace，管理员填入 javascript:alert(...) 时，
// 所有访问 /apps 的普通用户点击后都会在本站域内执行脚本（存储型 XSS）。
// 即使管理员是可信角色，这一层校验也必须保留：数据库可能被直接改写，
// 且历史数据里可能已存在危险取值。
//
// 规则：只接受 http / https 绝对地址；其余（javascript:、data:、file:、
// 协议相对 //host、相对路径）一律返回空串，由调用方决定是否报错。
// 返回空串表示「不合法」，调用方需自行判断原始输入是否为空以区分
// 「未填写」与「填写了非法值」。
// sanitizeAssetURL 归一化「会被渲染成资源引用」的地址（站点 Logo / Favicon、
// 登录提供商 Logo）。与 sanitizeExternalURL 的区别是额外允许站内绝对路径
// （如内置的 /images/logo.svg）：品牌资源经常就放在本站 public 目录下，
// 只允许 http/https 会把这些合法取值一并拒掉。
//
// 仍然拒绝协议相对地址（//host）与含反斜杠的路径：前者会指向外部站点却看起来
// 像站内路径，是协议降级与钓鱼的常见载体；后者的 "\" 会被浏览器当作 "/" 规整，
// 同样能凑出发往外部站点的地址。
//
// 复用 sanitizeExternalURL 实现，保证「危险协议一律拒绝」的规则只有一份。
func sanitizeAssetURL(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", true
	}
	if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") {
		// 站内绝对路径：不含控制字符即视为合法。
		if strings.ContainsAny(v, "\r\n\t") {
			return "", false
		}
		// 反斜杠必须拒绝：浏览器解析相对地址时把 "\" 等同于 "/"，
		// "/\evil.example.com/x.svg" 会被规整成 "https://evil.example.com/x.svg"
		// ——外观是站内路径，实际指向外部站点，与协议相对地址同源同类问题。
		if strings.Contains(v, "\\") {
			return "", false
		}
		return v, true
	}
	return sanitizeExternalURL(v)
}

func sanitizeExternalURL(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", true
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	// http/https 必须有 host，否则形如 "http:///x" 无法渲染成有效链接。
	if u.Host == "" {
		return "", false
	}
	return v, true
}
