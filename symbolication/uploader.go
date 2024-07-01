package symbolication

import (
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
)

var _ Uploader = (*NoopUploader)(nil)

type NoopUploader struct{}

func (n *NoopUploader) HandleExecutable(_ *pfelf.Reference, _ libpf.FileID) {}

func NewNoopUploader() Uploader {
	return &NoopUploader{}
}
