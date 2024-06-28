//go:build integration && linux

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracer

import (
	"context"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/host"
	hostmeta "github.com/elastic/otel-profiling-agent/hostmetadata/host"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/rlimit"
	"github.com/elastic/otel-profiling-agent/support"
	"github.com/elastic/otel-profiling-agent/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forceContextSwitch makes sure two Go threads are running concurrently
// and that there will be a context switch between those two.
func forceContextSwitch() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		wg.Done()
	}(wg)
	wg.Wait()
}

// runKernelFrameProbe executes a perf event on the sched/sched_switch tracepoint
// that sends a selection of hand-crafted, predictable traces.
func runKernelFrameProbe(t *testing.T, tracer *Tracer) {
	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	err = coll.RewriteMaps(tracer.ebpfMaps) //nolint:staticcheck
	require.NoError(t, err)

	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	prog, err := cebpf.NewProgram(coll.Programs["tracepoint__sched_switch"])
	require.NoError(t, err)
	defer prog.Close()

	ev, err := link.Tracepoint("sched", "sched_switch", prog, nil)
	require.NoError(t, err)
	t.Logf("probe for Kernel frames installed on sched/sched_switch")

	// Manually trigger the tracepoint on sched/sched_switch.
	forceContextSwitch()

	t.Logf("tracepoint sched_switch triggered")
	err = ev.Close()
	require.NoError(t, err)
}

func validateTrace(t *testing.T, numKernelFrames int, expected, returned *host.Trace) {
	t.Helper()

	assert.Equal(t, len(expected.Frames), len(returned.Frames)-numKernelFrames)

	for i, expFrame := range expected.Frames {
		retFrame := returned.Frames[numKernelFrames+i]
		assert.Equal(t, expFrame.File, retFrame.File)
		assert.Equal(t, expFrame.Lineno, retFrame.Lineno)
		assert.Equal(t, expFrame.Type, retFrame.Type)
	}
}

type mockIntervals struct{}

func (f mockIntervals) MonitorInterval() time.Duration    { return 1 * time.Second }
func (f mockIntervals) TracePollInterval() time.Duration  { return 250 * time.Millisecond }
func (f mockIntervals) PIDCleanupInterval() time.Duration { return 1 * time.Second }

type mockReporter struct{}

func (f mockReporter) ExecutableMetadata(_ context.Context, _ libpf.FileID, _, _ string) {}
func (f mockReporter) ReportFallbackSymbol(_ libpf.FrameID, _ string)                    {}
func (f mockReporter) FrameMetadata(_ libpf.FileID, _ libpf.AddressOrLineno, _ util.SourceLineno,
	_ uint32, _, _ string) {
}
func (f mockReporter) ProcessMetadata(_ context.Context, _ util.PID, _ string) {}

func generateMaxLengthTrace() host.Trace {
	var trace host.Trace
	for i := 0; i < support.MaxFrameUnwinds; i++ {
		trace.Frames = append(trace.Frames, host.Frame{
			File:   ^host.FileID(i),
			Lineno: libpf.AddressOrLineno(i),
			Type:   support.FrameMarkerNative,
		})
	}
	return trace
}

func TestTraceTransmissionAndParsing(t *testing.T) {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "tracer-integration-test-cache")
	require.NoError(t, err)

	var presentCores uint16
	presentCores, err = hostmeta.PresentCPUCores()
	require.NoError(t, err)

	err = config.SetConfiguration(&config.Config{
		ProjectID:        42,
		CacheDirectory:   dir,
		SecretToken:      "secret",
		PresentCPUCores:  presentCores,
		SamplesPerSecond: 20,
	})
	require.NoError(t, err)

	enabledTracers, _ := config.ParseTracers("")
	enabledTracers.Enable(config.PythonTracer)
	tracer, err := NewTracer(ctx, &mockReporter{}, nil, &mockIntervals{}, enabledTracers, false)
	require.NoError(t, err)

	traceChan := make(chan *host.Trace, 16)
	err = tracer.StartMapMonitors(ctx, traceChan)
	require.NoError(t, err)

	runKernelFrameProbe(t, tracer)

	traces := make(map[uint8]*host.Trace)
	timeout := time.NewTimer(1 * time.Second)

	// Wait 1 second for traces to arrive.
Loop:
	for {
		select {
		case <-timeout.C:
			break Loop
		case trace := <-traceChan:
			require.GreaterOrEqual(t, len(trace.Comm), 4)
			require.Equal(t, "\xAA\xBB\xCC", trace.Comm[0:3])
			traces[trace.Comm[3]] = trace
		}
	}

	tests := map[string]struct {
		// id identifies the trace to inspect (encoded in COMM[3]).
		id uint8
		// hasKernelFrames indicates if the trace should contain kernel frames.
		hasKernelFrames bool
		// userSpaceTrace holds a single Trace with just the user-space portion of the trace
		// that will be verified against the returned Trace.
		userSpaceTrace host.Trace
	}{
		"Single Native Frame": {
			id: 1,
			userSpaceTrace: host.Trace{
				Frames: []host.Frame{{
					File:   1337,
					Lineno: 21,
					Type:   support.FrameMarkerNative,
				}},
			},
		},
		"Single Native Frame with Kernel Frames": {
			id:              2,
			hasKernelFrames: true,
			userSpaceTrace: host.Trace{
				Frames: []host.Frame{{
					File:   1337,
					Lineno: 21,
					Type:   support.FrameMarkerNative,
				}},
			},
		},
		"Three Python Frames": {
			id: 3,
			userSpaceTrace: host.Trace{
				Frames: []host.Frame{{
					File:   1337,
					Lineno: 42,
					Type:   support.FrameMarkerNative,
				}, {
					File:   1338,
					Lineno: 21,
					Type:   support.FrameMarkerNative,
				}, {
					File:   1339,
					Lineno: 22,
					Type:   support.FrameMarkerPython,
				}},
			},
		},
		"Maximum Length Trace": {
			id:              4,
			hasKernelFrames: true,
			userSpaceTrace:  generateMaxLengthTrace(),
		},
	}

	for name, testcase := range tests {
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			trace, ok := traces[testcase.id]
			require.Truef(t, ok, "trace ID %d not received", testcase.id)

			var numKernelFrames int
			for _, frame := range trace.Frames {
				if frame.Type == support.FrameMarkerKernel {
					numKernelFrames++
				}
			}

			userspaceFrameCount := len(trace.Frames) - numKernelFrames
			assert.Equal(t, len(testcase.userSpaceTrace.Frames), userspaceFrameCount)
			assert.False(t, !testcase.hasKernelFrames && numKernelFrames > 0,
				"unexpected kernel frames")

			// If this check fails it _could_ be a false positive, in that there is not
			// in fact anything wrong with the code being tested. We hope that the
			// kernel stack we capture has at least two frames, but it is possible that
			// it does not. If this happens frequently we should consider if there is a
			// different approach to checking this property without the possibility of
			// false positives.
			assert.Falsef(t, testcase.hasKernelFrames && numKernelFrames < 2,
				"expected at least 2 kernel frames, but got %d", numKernelFrames)

			t.Logf("Received %d user frames and %d kernel frames",
				userspaceFrameCount, numKernelFrames)

			validateTrace(t, numKernelFrames, &testcase.userSpaceTrace, trace)
		})
	}
}
