package storage

import "errors"

// ErrNotFound 表示对象在后端不存在。
// 上层据此返回 404，并与后端故障（连接失败等）区分开。
var ErrNotFound = errors.New("storage: object not found")
