// Package storage abstracts file/blob storage behind a common interface.
// The primary use case is user avatars and general file uploads, backed by
// local disk or S3-compatible object stores.
package storage

import (
	"context"
	"io"
	"strings"
)

// Object describes a stored blob.
type Object struct {
	// Key is the stable object identifier within the backend.
	Key string
	// URL 是后端自身给出的可访问地址（仅对象存储可能有，如 S3 的公开前缀）。
	// 本地后端留空：文件的对外入口统一是 /api/v1/files/{publicId}，
	// 由文件元数据生成，与存储键无关。
	URL string
}

// Provider is the storage abstraction used by OpenIdP for user uploads.
type Provider interface {
	// Put stores the data under key and returns the object's public reference.
	Put(ctx context.Context, key string, data io.Reader, contentType string) (Object, error)
	// Get opens a previously stored object for reading.
	// 调用方负责关闭返回的 ReadCloser。对象不存在时返回 ErrNotFound，
	// 便于上层区分「文件缺失」与「后端故障」。
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	// Delete removes the object. 删除不存在的对象视为成功（幂等），
	// 这样孤儿回收重试时不会因竞态报错。
	Delete(ctx context.Context, key string) error
}

// Config holds the settings used to build a storage Provider.
type Config struct {
	// Backend is "local" (default) or "s3".
	Backend string
	// Local base directory (used by local backend).
	LocalDir string
	// S3 connection settings (used by s3 backend).
	S3Endpoint      string
	S3Bucket        string
	S3Region        string
	S3KeyID         string
	S3Secret        string
	S3PublicBaseURL string
}

// New builds a Provider from Config, defaulting to the local backend.
func New(cfg Config) Provider {
	if strings.EqualFold(cfg.Backend, "s3") && cfg.S3Bucket != "" {
		return NewS3(cfg.S3Endpoint, cfg.S3Bucket, cfg.S3Region, cfg.S3KeyID, cfg.S3Secret, cfg.S3PublicBaseURL)
	}
	return NewLocal(cfg.LocalDir)
}
