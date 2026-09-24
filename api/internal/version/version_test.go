package version

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 构建元数据测试。
//
// 背景：version 包此前零测试。它看似简单，但 /api/version 端点与启动日志
// 都依赖它；字段若被误改或 JSON 标签写错，运维排障会拿到错误信息。
// 本文件锁定默认占位值与 JSON 序列化契约。
// ---------------------------------------------------------------------------

// TestDefaultsArePlaceholders 未通过 ldflags 注入时应有可辨识的默认值，
// 而不是空字符串（空串会让人误以为注入成功但值为空）。
func TestDefaultsArePlaceholders(t *testing.T) {
	if Version == "" || Commit == "" || BuildDate == "" {
		t.Errorf("默认值不应为空: version=%q commit=%q buildDate=%q", Version, Commit, BuildDate)
	}
}

func TestGetReflectsCurrentValues(t *testing.T) {
	// 保存并恢复，避免影响其他测试
	ov, oc, ob := Version, Commit, BuildDate
	defer func() { Version, Commit, BuildDate = ov, oc, ob }()

	Version, Commit, BuildDate = "1.2.3", "abc123", "2026-09-04T00:00:00Z"
	info := Get()
	if info.Version != "1.2.3" || info.Commit != "abc123" || info.BuildDate != "2026-09-04T00:00:00Z" {
		t.Errorf("Get() = %+v，未反映当前变量值", info)
	}
}

// TestInfoJSONTags /api/version 的响应字段由 JSON 标签决定；
// 标签写错会导致前端读不到版本号（例如误写成 version_ 或驼峰不一致）。
func TestInfoJSONTags(t *testing.T) {
	b, err := json.Marshal(Get())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"version"`, `"commit"`, `"buildDate"`} {
		if !strings.Contains(s, want) {
			t.Errorf("序列化结果缺少 %q: %s", want, s)
		}
	}
	// 不应出现下划线风格（防止标签被误改）
	for _, bad := range []string{`"build_date"`, `"Version"`} {
		if strings.Contains(s, bad) {
			t.Errorf("序列化结果含非预期字段 %q: %s", bad, s)
		}
	}
}

// TestInfoIsDecodable 确保响应可被标准反序列化（字段名与类型自洽）。
func TestInfoIsDecodable(t *testing.T) {
	ov, oc, ob := Version, Commit, BuildDate
	defer func() { Version, Commit, BuildDate = ov, oc, ob }()

	Version, Commit, BuildDate = "9.9.9", "deadbeef", time.Now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(Get())
	var got Info
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Version != "9.9.9" || got.Commit != "deadbeef" {
		t.Errorf("往返后 = %+v", got)
	}
}
