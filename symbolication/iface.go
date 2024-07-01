package symbolication

import (
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
)

type Uploader interface {
	HandleExecutable(elfRef *pfelf.Reference, fileID libpf.FileID)
}
