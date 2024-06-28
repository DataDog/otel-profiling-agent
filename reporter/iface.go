/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"context"
	"time"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/util"
)

// Reporter is the top-level interface implemented by a full reporter.
type Reporter interface {
	TraceReporter
	SymbolReporter
	HostMetadataReporter
	MetricsReporter

	// Stop triggers a graceful shutdown of the reporter.
	Stop()
	// GetMetrics returns the reporter internal metrics.
	GetMetrics() Metrics
}

type TraceReporter interface {
	// ReportFramesForTrace accepts a trace with the corresponding frames
	// and caches this information before a periodic reporting to the backend.
	ReportFramesForTrace(trace *libpf.Trace)

	// ReportCountForTrace accepts a hash of a trace with a corresponding count and
	// caches this information before a periodic reporting to the backend.
	ReportCountForTrace(traceHash libpf.TraceHash, timestamp libpf.UnixTime64,
		count uint16, comm, podName, containerName, apmServiceName string)

	// ReportTraceEvent accepts a trace event (trace metadata with frames and counts)
	// and caches it for reporting to the backend. It returns true if the event was
	// enqueued for reporting, and false if the event was ignored.
	ReportTraceEvent(trace *libpf.Trace, timestamp libpf.UnixTime64,
		comm, podName, containerName, apmServiceName string, pid util.PID)

	// SupportsReportTraceEvent returns true if the reporter supports reporting trace events
	// via ReportTraceEvent().
	SupportsReportTraceEvent() bool
}

type SymbolReporter interface {
	// ReportFallbackSymbol enqueues a fallback symbol for reporting, for a given frame.
	ReportFallbackSymbol(frameID libpf.FrameID, symbol string)

	// ExecutableMetadata accepts a fileID with the corresponding filename
	// and caches this information before a periodic reporting to the backend.
	ExecutableMetadata(ctx context.Context, fileID libpf.FileID, fileName, buildID string)

	// FrameMetadata accepts metadata associated with a frame and caches this information before
	// a periodic reporting to the backend.
	FrameMetadata(fileID libpf.FileID, addressOrLine libpf.AddressOrLineno,
		lineNumber util.SourceLineno, functionOffset uint32, functionName, filePath string)

	// ProcessMetadata accepts metadata associated with a process and caches this information
	// before a periodic reporting to the backend.
	ProcessMetadata(ctx context.Context, pid util.PID, exe string)
}

type HostMetadataReporter interface {
	// ReportHostMetadata enqueues host metadata for sending (to the collection agent).
	ReportHostMetadata(metadataMap map[string]string)

	// ReportHostMetadataBlocking sends host metadata to the collection agent.
	ReportHostMetadataBlocking(ctx context.Context, metadataMap map[string]string,
		maxRetries int, waitRetry time.Duration) error
}

type MetricsReporter interface {
	// ReportMetrics accepts an id with a corresponding value and caches this
	// information before a periodic reporting to the backend.
	ReportMetrics(timestamp uint32, ids []uint32, values []int64)
}
