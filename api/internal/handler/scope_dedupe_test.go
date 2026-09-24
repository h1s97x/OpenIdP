package handler

import "testing"

// TestScopeInfosForDeduplicatesCustomScopes 回归：自定义权限去重。
// scopeInfosFor 的入参来自 JSON 数组（如 grants.scopes），允许出现重复项；
// 此前自定义权限分支只判 scopeOrder 成员，不判是否已输出，重复项会被重复追加，
// 导致授权页 / 「我的授权」权限明细重复（React key 重复告警）、计数虚高。
func TestScopeInfosForDeduplicatesCustomScopes(t *testing.T) {
	out := scopeInfosFor([]string{"openid", "custom", "custom"})
	if len(out) != 2 {
		t.Fatalf("期望 2 项（openid + 去重后的 custom），实际 %d 项：%+v", len(out), out)
	}
	if out[0].Key != "openid" || out[1].Key != "custom" {
		t.Fatalf("权限顺序或内容不符：%+v", out)
	}

	// 内置权限同样只出现一次，即使入参重复。
	out = scopeInfosFor([]string{"openid", "openid", "email"})
	if len(out) != 2 {
		t.Fatalf("期望 2 项，实际 %d 项：%+v", len(out), out)
	}
	seen := map[string]int{}
	for _, s := range out {
		seen[s.Key]++
	}
	for k, n := range seen {
		if n != 1 {
			t.Fatalf("权限 %q 重复出现 %d 次", k, n)
		}
	}
}

// TestScopeInfosForOmitsNonExistentAddress 回归：授权应用卡片不得显示不存在的
// 地址权限。address 并非本服务实际提供的能力（权限项已禁用），历史授权数据
// 里可能残留该 scope，展示层必须直接忽略，而不是当作自定义权限列出来。
func TestScopeInfosForOmitsNonExistentAddress(t *testing.T) {
	out := scopeInfosFor([]string{"openid", "profile", "address"})
	for _, s := range out {
		if s.Key == "address" {
			t.Fatalf("地址权限不应出现在权限明细中：%+v", out)
		}
	}
	if len(out) != 2 {
		t.Fatalf("期望 2 项（openid + profile），实际 %d 项：%+v", len(out), out)
	}

	// 自定义权限仍应正常展示，不受影响。
	out = scopeInfosFor([]string{"openid", "custom_scope"})
	if len(out) != 2 || out[1].Key != "custom_scope" {
		t.Fatalf("自定义权限应保留：%+v", out)
	}
}
