package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Local 是本地文件系统实现：对象存放在 BaseDir 下，按 key 分片。
//
// 说明：本类型不再维护「公网 URL 前缀」。历史上的 LocalURLPrefix（/uploads）
// 是一处死配置——本地目录从未被任何路由服务过，文件的对外地址统一由文件的
// publicId 生成（/api/v1/files/{publicId}，见 models.File.URL）。
// 保留一个永远不会被访问到的 URL 前缀，只会让人误以为 /uploads 可用。
type Local struct {
	// BaseDir is the root directory where objects are stored.
	BaseDir string
}

// NewLocal creates a local Provider rooted at baseDir.
func NewLocal(baseDir string) *Local {
	return &Local{BaseDir: baseDir}
}

// Put writes data to key under BaseDir, creating parent directories as needed.
// 返回的 Object.URL 为空：对外地址由上层按文件 publicId 生成，而不是由存储键拼出。
func (l *Local) Put(_ context.Context, key string, data io.Reader, _ string) (Object, error) {
	path := l.safePath(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Object{}, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return Object{}, err
	}
	defer f.Close()
	if _, err := io.Copy(f, data); err != nil {
		return Object{}, err
	}
	return Object{Key: key}, nil
}

// Get opens the stored object at key for reading.
func (l *Local) Get(_ context.Context, key string) (io.ReadCloser, error) {
	path := l.safePath(key)
	// 二次校验解析后的路径仍位于 BaseDir 内，防止 key 穿越到目录之外。
	if !l.contains(path) {
		return nil, ErrNotFound
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || fi.IsDir() {
		_ = f.Close()
		return nil, ErrNotFound
	}
	return f, nil
}

// Delete removes the stored object at key. 删除不存在的对象视为成功。
func (l *Local) Delete(_ context.Context, key string) error {
	path := l.safePath(key)
	if !l.contains(path) {
		return ErrNotFound
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	// 清理对象删除后遗留的空目录，避免长期运行留下大量空壳目录。
	// 清理失败不影响删除结果，故忽略错误。
	if dir := filepath.Dir(path); dir != filepath.Clean(l.BaseDir) {
		_ = os.Remove(dir)
	}
	return nil
}

// safePath resolves key under BaseDir while preventing path traversal.
func (l *Local) safePath(key string) string {
	clean := filepath.Clean("/" + key)
	clean = strings.TrimPrefix(clean, "/")
	return filepath.Join(l.BaseDir, filepath.FromSlash(clean))
}

// contains 校验路径解析后仍位于 BaseDir 内（防目录穿越）。
func (l *Local) contains(path string) bool {
	root := filepath.Clean(l.BaseDir)
	if root == "" || root == "." || root == string(filepath.Separator) {
		return true
	}
	return strings.HasPrefix(filepath.Clean(path)+string(filepath.Separator), root+string(filepath.Separator))
}
