package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// S3 is a minimal S3-compatible object-store Provider (AWS Signature V4) that
// uses only the Go standard library. It supports the common Put/Get/Delete
// operations against S3 and S3-compatible services (MinIO, R2, OSS, COS).
type S3 struct {
	Endpoint string // e.g. https://s3.amazonaws.com
	Bucket   string
	Region   string
	KeyID    string
	Secret   string
	// PublicBaseURL, when set, is used to build the public object URL.
	PublicBaseURL string
	client        *http.Client
}

// NewS3 creates an S3 Provider.
func NewS3(endpoint, bucket, region, keyID, secret, publicBaseURL string) *S3 {
	return &S3{
		Endpoint:      strings.TrimSuffix(endpoint, "/"),
		Bucket:        bucket,
		Region:        region,
		KeyID:         keyID,
		Secret:        secret,
		PublicBaseURL: strings.TrimSuffix(publicBaseURL, "/"),
		client:        &http.Client{Timeout: 30 * time.Second},
	}
}

// Put uploads data to key in the bucket.
func (s *S3) Put(ctx context.Context, key string, data io.Reader, contentType string) (Object, error) {
	body, err := io.ReadAll(data)
	if err != nil {
		return Object{}, err
	}
	url := s.objectURL(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return Object{}, err
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	s.sign(req, body)
	resp, err := s.client.Do(req)
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return Object{}, fmt.Errorf("s3 put %s: %s", key, resp.Status)
	}
	base := s.PublicBaseURL
	if base == "" {
		base = s.Endpoint + "/" + s.Bucket
	}
	return Object{Key: key, URL: base + "/" + key}, nil
}

// Get opens the stored object at key for reading.
func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(key), nil)
	if err != nil {
		return nil, err
	}
	s.sign(req, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return nil, ErrNotFound
	}
	if resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("s3 get %s: %s", key, resp.Status)
	}
	return resp.Body, nil
}

// Delete removes the object at key. 删除不存在的对象视为成功。
func (s *S3) Delete(ctx context.Context, key string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.objectURL(key), nil)
	if err != nil {
		return err
	}
	s.sign(req, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent || resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("s3 delete %s: %s", key, resp.Status)
}

// objectURL builds the canonical object URL for a key.
func (s *S3) objectURL(key string) string {
	return fmt.Sprintf("%s/%s/%s", s.Endpoint, s.Bucket, escapeKey(key))
}

// escapeKey 对 key 的各路径片段做转义，保留 "/" 作为分隔符。
// 避免 key 中的特殊字符（?、#、空格）破坏 URL 结构与签名。
func escapeKey(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(url.PathEscape(p), "+", "%20")
	}
	return strings.Join(parts, "/")
}

// sign applies AWS Signature V4 to the request.
func (s *S3) sign(req *http.Request, body []byte) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256Hex(body)
	if body == nil {
		// GET/DELETE 没有请求体：SigV4 约定此时对 "UNSIGNED-PAYLOAD" 取摘要，
		// 而不是对空字符串取摘要，否则 S3 会拒绝签名。
		payloadHash = sha256Hex([]byte("UNSIGNED-PAYLOAD"))
	}
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	// headers to sign
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := "host:" + req.Host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		req.URL.RawQuery,
		canonicalHeaders,
		"",
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + s.Region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))

	signingKey := hmacSHA256([]byte("AWS4"+s.Secret), dateStamp)
	signingKey = hmacSHA256(signingKey, s.Region)
	signingKey = hmacSHA256(signingKey, "s3")
	signingKey = hmacSHA256(signingKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	req.Header.Set("Authorization",
		fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
			s.KeyID, scope, signedHeaders, signature))
}

func sha256Hex(b []byte) string {
	if b == nil {
		b = []byte{}
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
