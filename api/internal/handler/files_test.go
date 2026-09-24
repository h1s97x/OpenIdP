package handler

import (
	"net/http"
	"testing"
)

// mimeMatches 是上传类型校验的核心：SVG 是 XML 文本，Go 的 DetectContentType
// 永远嗅探不出 image/svg+xml（只给 text/xml 或 text/plain），因此需要按内容
// 判定。这段逻辑一旦放宽，把 HTML 放行成 SVG 就等于开放了存储型 XSS，
// 故用测试把「放行 SVG」与「拒绝 HTML / 纯文本」两条边界都钉死。
func TestMimeMatches(t *testing.T) {
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>`)
	svgXMLDecl := []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")
	svgLowerDecl := []byte("<?xml version='1.0' encoding='UTF-8'?><SVG xmlns=\"http://www.w3.org/2000/svg\"></SVG>")
	png := []byte("\x89PNG\r\n\x1a\n" + string(make([]byte, 64)))
	html := []byte("<html><script>alert(1)</script></html>")
	htmlWithXmlDecl := []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?><html><script>alert(1)</script></html>")
	plain := []byte("just some plain text, not svg")

	cases := []struct {
		name     string
		sniffed  string
		expected string
		buf      []byte
		want     bool
	}{
		// SVG：嗅探给 text/xml / text/plain 都要放行，只要内容确实是 <svg 开头。
		{"svg as text/xml", "text/xml; charset=utf-8", "image/svg+xml", svg, true},
		{"svg with xml declaration", "text/xml; charset=utf-8", "image/svg+xml", svgXMLDecl, true},
		{"svg with single-quoted declaration and uppercase tag", "text/xml; charset=utf-8", "image/svg+xml", svgLowerDecl, true},
		{"svg as text/plain", "text/plain; charset=utf-8", "image/svg+xml", svg, true},

		// 安全边界：HTML / 纯文本不得被当成 SVG 放行。
		{"html rejected as svg", "text/xml; charset=utf-8", "image/svg+xml", html, false},
		{"html with xml declaration rejected as svg", "text/xml; charset=utf-8", "image/svg+xml", htmlWithXmlDecl, false},
		{"plain text rejected as svg", "text/plain; charset=utf-8", "image/svg+xml", plain, false},
		{"svg extension with image/png content rejected", "image/png", "image/svg+xml", png, false},

		// 位图：沿用严格相等，不得因为 SVGu3001/text 规则而放宽。
		{"png matches png", "image/png", "image/png", png, true},
		{"mismatched bitmap rejected", "image/jpeg", "image/png", png, false},
		{"non-svg expected ignores svg rule", "text/xml", "image/png", svg, false},
		{"non-svg expected ignores svg rule (jpeg)", "text/plain", "image/jpeg", svg, false},

		// Go 对文本类嗅探会附带 ``; charset=utf-8``：此前严格相等导致
		// txt/md/csv/json 附件全部被误拒，这里用真实嗅探产出钉死行为。
		{"txt as sniffed by http.DetectContentType", "text/plain; charset=utf-8", "text/plain", []byte("hello text"), true},
		{"md sniffed as plain text accepted", "text/plain; charset=utf-8", "text/markdown", []byte("# Title\\n\\nbody"), true},
		{"csv sniffed as plain text accepted", "text/plain; charset=utf-8", "text/csv", []byte("a,b,c\\n1,2,3"), true},
		{"json sniffed as plain text accepted", "text/plain; charset=utf-8", "application/json", []byte(`{"a":1}`), true},
		{"json declared with charset", "application/json; charset=utf-8", "application/json", []byte(`{"a":1}`), true},
		// HTML 仍不得被文本白名单接纳。
		{"html rejected for txt", "text/html; charset=utf-8", "text/plain", []byte("<html></html>"), false},
		{"html rejected for md", "text/html; charset=utf-8", "text/markdown", []byte("<html></html>"), false},
		{"png content rejected for txt", "image/png", "text/plain", png, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mimeMatches(c.sniffed, c.expected, c.buf); got != c.want {
				t.Fatalf("mimeMatches(%q, %q) = %v, want %v", c.sniffed, c.expected, got, c.want)
			}
		})
	}
}

// TestMimeMatchesWithRealSniff 用 http.DetectContentType 的真实产出验证文本附件。
//
// 之前的用例把嗅探结果手工写成裸 "text/plain"，绕过了 Go 实际会附加
// "charset=utf-8" 的事实，导致用例通过而功能不可用。这里直接喂真实产出。
func TestMimeMatchesWithRealSniff(t *testing.T) {
	cases := []struct {
		ext      string
		expected string
		body     []byte
	}{
		{".txt", "text/plain", []byte("hello text")},
		{".md", "text/markdown", []byte("# Title\n\nbody")},
		{".csv", "text/csv", []byte("a,b,c\n1,2,3")},
		{".json", "application/json", []byte(`{"a":1}`)},
		{".svg", "image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)},
	}
	for _, c := range cases {
		sniffed := http.DetectContentType(c.body)
		if !mimeMatches(sniffed, c.expected, c.body) {
			t.Errorf("%s: mimeMatches(%q, %q) = false, want true", c.ext, sniffed, c.expected)
		}
	}
	// HTML 内容冒充 .txt 必须被拒绝。
	html := []byte("<html><script>alert(1)</script></html>")
	if mimeMatches(http.DetectContentType(html), "text/plain", html) {
		t.Error("html content must not pass as text/plain")
	}
}

// 扩展名白名单必须包含 SVG，否则前端 accept 允许选中的文件会被后端拒绝。
func TestAllowedImageExtIncludesSVG(t *testing.T) {
	if got := allowedImageExt[".svg"]; got != "image/svg+xml" {
		t.Fatalf("allowedImageExt[\".svg\"] = %q, want %q", got, "image/svg+xml")
	}
	if got := allowedAttachmentExt[".svg"]; got != "image/svg+xml" {
		t.Fatalf("allowedAttachmentExt[\".svg\"] = %q, want %q", got, "image/svg+xml")
	}
}
