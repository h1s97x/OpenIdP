package models

import "testing"

// ---------------------------------------------------------------------------
// 数据模型测试。
//
// 背景：models 包此前零测试。当前包内唯一的逻辑是 File.URL()，
// 它决定头像/附件对外的访问路径，被多处直接依赖，故锁定其契约。
// ---------------------------------------------------------------------------

// TestFileURL 文件访问路径必须是内容寻址前缀 + publicId。
func TestFileURL(t *testing.T) {
	f := &File{PublicID: "abcdef0123456789abcdef01"}
	if got, want := f.URL(), "/api/v1/files/abcdef0123456789abcdef01"; got != want {
		t.Errorf("URL() = %q, want %q", got, want)
	}
}

// TestFileURLEmptyPublicID publicId 为空时不应产出残缺路径
// （否则前端可能拼出 /api/v1/files/ 导致意外命中列表接口）。
func TestFileURLEmptyPublicID(t *testing.T) {
	if got := (&File{}).URL(); got != "" {
		t.Errorf("空 publicId 的 URL() = %q, want 空串", got)
	}
	if got := (&File{PublicID: "   "}).URL(); got == "/api/v1/files/" {
		t.Errorf("空白 publicId 不应产出裸前缀: %q", got)
	}
}

// TestFileURLNilReceiver nil 接收者不应 panic——调用方常在可空字段上直接调用。
func TestFileURLNilReceiver(t *testing.T) {
	var f *File
	if got := f.URL(); got != "" {
		t.Errorf("nil File 的 URL() = %q, want 空串", got)
	}
}

// TestDeletionStatusConstants 注销流程的状态常量不得重复或为空，
// 否则状态机判断会失效。
func TestDeletionStatusConstants(t *testing.T) {
	consts := map[string]string{
		"Pending":   DeletionStatusPending,
		"Approved":  DeletionStatusApproved,
		"Rejected":  DeletionStatusRejected,
		"Cancelled": DeletionStatusCancelled,
		"Completed": DeletionStatusCompleted,
	}
	seen := map[string]string{}
	for name, v := range consts {
		if v == "" {
			t.Errorf("%s 状态常量不应为空", name)
			continue
		}
		if prev, dup := seen[v]; dup {
			t.Errorf("状态常量重复: %s 与 %s 同为 %q", prev, name, v)
		}
		seen[v] = name
	}
}

// TestFilePurposeConstants 文件用途常量应互斥，便于按用途筛选。
func TestFilePurposeConstants(t *testing.T) {
	if FilePurposeAvatar == FilePurposeAttachment {
		t.Errorf("头像与附件用途不应相同: %q", FilePurposeAvatar)
	}
	if FilePurposeAvatar == "" || FilePurposeAttachment == "" {
		t.Error("文件用途常量不应为空")
	}
}
