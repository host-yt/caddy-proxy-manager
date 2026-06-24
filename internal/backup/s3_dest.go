package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3-compatible destination (Hetzner Object Storage, AWS S3, MinIO, etc.).
//
// Config keys:
//
//	endpoint        e.g. "fsn1.your-objectstorage.com" or "s3.amazonaws.com"
//	                (host[:port], scheme stripped — `use_ssl` controls)
//	region          e.g. "eu-central-1"
//	bucket          target bucket (must already exist)
//	access_key      access key id (required)
//	secret_key      secret access key (required)
//	prefix          optional key prefix, e.g. "hpg/"
//	use_ssl         "1" = HTTPS (default), "0" = HTTP
//	path_style      "1" force path-style addressing (MinIO, some providers)
type s3Dest struct {
	client *minio.Client
	bucket string
	prefix string
}

func newS3Dest(cfg map[string]string) (*s3Dest, error) {
	endpoint := strings.TrimSpace(cfg["endpoint"])
	if endpoint == "" {
		return nil, errors.New("s3: endpoint required")
	}
	// Strip scheme if user pasted a URL.
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" && u.Scheme != "" {
		endpoint = u.Host
	}
	// SSRF guard: the endpoint host drives an outbound connect; reject
	// loopback / RFC1918 / link-local so an admin can't probe internal
	// services by configuring a backup destination.
	hostOnly := endpoint
	if i := strings.IndexByte(hostOnly, ':'); i > 0 {
		hostOnly = hostOnly[:i]
	}
	if err := validateDestHost(hostOnly); err != nil {
		return nil, fmt.Errorf("s3: %w", err)
	}
	bucket := strings.TrimSpace(cfg["bucket"])
	if bucket == "" {
		return nil, errors.New("s3: bucket required")
	}
	ak := strings.TrimSpace(cfg["access_key"])
	sk := cfg["secret_key"]
	if ak == "" || sk == "" {
		return nil, errors.New("s3: access_key + secret_key required")
	}
	useSSL := cfg["use_ssl"] != "0"
	opts := &minio.Options{
		Creds:  credentials.NewStaticV4(ak, sk, ""),
		Secure: useSSL,
		Region: strings.TrimSpace(cfg["region"]),
	}
	if cfg["path_style"] == "1" {
		opts.BucketLookup = minio.BucketLookupPath
	}
	cli, err := minio.New(endpoint, opts)
	if err != nil {
		return nil, fmt.Errorf("s3: new client: %w", err)
	}
	return &s3Dest{
		client: cli,
		bucket: bucket,
		prefix: strings.TrimSpace(cfg["prefix"]),
	}, nil
}

func (d *s3Dest) keyWithPrefix(key string) string {
	if d.prefix == "" {
		return key
	}
	if strings.HasSuffix(d.prefix, "/") {
		return d.prefix + key
	}
	return d.prefix + "/" + key
}

func (d *s3Dest) Upload(ctx context.Context, key string, body io.Reader, size int64) error {
	if strings.Contains(key, "..") {
		return errors.New("s3: key contains traversal")
	}
	full := d.keyWithPrefix(key)
	if size < 0 {
		// Unknown size → use -1 to let minio-go pick multipart.
		size = -1
	}
	_, err := d.client.PutObject(ctx, d.bucket, full, body, size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("s3: put: %w", err)
	}
	return nil
}

func (d *s3Dest) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	if strings.Contains(key, "..") {
		return nil, errors.New("s3: key contains traversal")
	}
	obj, err := d.client.GetObject(ctx, d.bucket, d.keyWithPrefix(key), minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (d *s3Dest) Delete(ctx context.Context, key string) error {
	if strings.Contains(key, "..") {
		return errors.New("s3: key contains traversal")
	}
	full := d.keyWithPrefix(key)
	return d.client.RemoveObject(ctx, d.bucket, full, minio.RemoveObjectOptions{})
}
