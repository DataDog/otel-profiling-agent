package symbolication

import (
	"context"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
)

var _ Uploader = (*NoopUploader)(nil)

type NoopUploader struct{}

func (n *NoopUploader) HandleExecutable(_ context.Context, _ *pfelf.Reference,
	_ libpf.FileID) error {
	return nil
}

func NewNoopUploader() Uploader {
	return &NoopUploader{}
}
