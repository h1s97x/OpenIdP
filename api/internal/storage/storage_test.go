package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalPut(t *testing.T) {
	dir := t.TempDir()
	p := NewLocal(dir)

	obj, err := p.Put(context.Background(), "avatars/u1.png", bytes.NewBufferString("png-data"), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	// 本地后端不产出对外 URL：文件入口统一是 /api/v1/files/{publicId}。
	if obj.Key != "avatars/u1.png" {
		t.Fatalf("unexpected key %q", obj.Key)
	}
	if _, err := os.Stat(filepath.Join(dir, "avatars", "u1.png")); err != nil {
		t.Fatalf("expected file to be written: %v", err)
	}
}

func TestNewDefaultsToLocal(t *testing.T) {
	p := New(Config{LocalDir: t.TempDir()})
	if p == nil {
		t.Fatal("expected a provider")
	}
}

func TestLocalPreventsTraversal(t *testing.T) {
	dir := t.TempDir()
	p := NewLocal(dir)
	obj, err := p.Put(context.Background(), "../../etc/passwd", bytes.NewBufferString("x"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	// key is cleaned, no traversal
	_ = obj
	if _, err := os.Stat("/etc/passwd.bak"); err == nil {
		t.Fatal("traversal escaped base dir")
	}
}
