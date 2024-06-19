package symbolication

import (
	"context"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
)

type Uploader interface {
	HandleExecutable(ctx context.Context, elfRef *pfelf.Reference, fileID libpf.FileID) error
}
