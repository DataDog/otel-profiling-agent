/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracehandler

import (
	"testing"
	"time"

	"github.com/elastic/go-freelru"
	"github.com/stretchr/testify/require"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/libpf"
)

type fakeTimes struct {
	monitorInterval time.Duration
}

func defaultTimes() *fakeTimes {
	return &fakeTimes{monitorInterval: 1 * time.Hour}
}

func (ft *fakeTimes) MonitorInterval() time.Duration { return ft.monitorInterval }

// fakeTraceProcessor implements a fake TraceProcessor used only within the test scope.
type fakeTraceProcessor struct{}

// Compile time check to make sure fakeTraceProcessor satisfies the interfaces.
var _ TraceProcessor = (*fakeTraceProcessor)(nil)

func (f *fakeTraceProcessor) ConvertTrace(trace *host.Trace) *libpf.Trace {
	var newTrace libpf.Trace
	newTrace.Hash = libpf.NewTraceHash(uint64(trace.Hash), uint64(trace.Hash))
	return &newTrace
}

func (f *fakeTraceProcessor) SymbolizationComplete(libpf.KTime) {
}

// arguments holds the inputs to test the appropriate functions.
type arguments struct {
	// trace holds the arguments for the function HandleTrace().
	trace *host.Trace
	// delay specifies a time delay after input has been processed
	delay time.Duration
}

// reportedCount / reportedTrace hold the information reported from traceHandler
// via the reporter functions (reportCountForTrace / reportFramesForTrace).
type reportedCount struct {
	traceHash libpf.TraceHash
	count     uint16
}

type reportedTrace struct {
	traceHash libpf.TraceHash
}

type mockReporter struct {
	t              *testing.T
	reportedCounts []reportedCount
	reportedTraces []reportedTrace
}

func (m *mockReporter) ReportFramesForTrace(trace *libpf.Trace) {
	m.reportedTraces = append(m.reportedTraces, reportedTrace{traceHash: trace.Hash})
	m.t.Logf("reportFramesForTrace: new trace 0x%x", trace.Hash)
}

func (m *mockReporter) ReportCountForTrace(traceHash libpf.TraceHash,
	_ libpf.UnixTime32, count uint16, _, _, _, _ string, _ libpf.PID) {
	m.reportedCounts = append(m.reportedCounts, reportedCount{
		traceHash: traceHash,
		count:     count,
	})
	m.t.Logf("reportCountForTrace: 0x%x count: %d", traceHash, count)
}

func TestTraceHandler(t *testing.T) {
	tests := map[string]struct {
		input          []arguments
		expectedCounts []reportedCount
		expectedTraces []reportedTrace
		expireTimeout  time.Duration
	}{
		// no input simulates a case where no data is provided as input
		// to the functions of traceHandler.
		"no input": {input: []arguments{}},

		// simulates a single trace being received.
		"single trace": {input: []arguments{
			{trace: &host.Trace{Hash: host.TraceHash(0x1234)}},
		},
			expectedTraces: []reportedTrace{{traceHash: libpf.NewTraceHash(0x1234, 0x1234)}},
			expectedCounts: []reportedCount{
				{traceHash: libpf.NewTraceHash(0x1234, 0x1234), count: 1},
			},
		},

		// double trace simulates a case where the same trace is encountered in quick succession.
		"double trace": {input: []arguments{
			{trace: &host.Trace{Hash: host.TraceHash(4)}},
			{trace: &host.Trace{Hash: host.TraceHash(4)}},
		},
			expectedTraces: []reportedTrace{{traceHash: libpf.NewTraceHash(4, 4)}},
			expectedCounts: []reportedCount{
				{traceHash: libpf.NewTraceHash(4, 4), count: 1},
				{traceHash: libpf.NewTraceHash(4, 4), count: 1},
			},
		},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			r := &mockReporter{t: t}

			bpfTraceCache, err := freelru.New[host.TraceHash, libpf.TraceHash](
				1024, func(k host.TraceHash) uint32 { return uint32(k) })
			require.Nil(t, err)
			require.NotNil(t, t, bpfTraceCache)

			umTraceCache, err := freelru.New[libpf.TraceHash, libpf.Void](
				1024, libpf.TraceHash.Hash32)
			require.Nil(t, err)
			require.NotNil(t, t, umTraceCache)

			tuh := &traceHandler{
				traceProcessor: &fakeTraceProcessor{},
				bpfTraceCache:  bpfTraceCache,
				umTraceCache:   umTraceCache,
				reporter:       r,
				times:          defaultTimes(),
			}

			for _, input := range test.input {
				tuh.HandleTrace(input.trace)
				time.Sleep(input.delay)
			}

			if len(r.reportedCounts) != len(test.expectedCounts) {
				t.Fatalf("Expected %d reported counts but got %d",
					len(test.expectedCounts), len(r.reportedCounts))
			}
			if len(r.reportedTraces) != len(test.expectedTraces) {
				t.Fatalf("Expected %d reported traces but got %d",
					len(test.expectedTraces), len(r.reportedTraces))
			}

			for idx, trace := range test.expectedTraces {
				// Expected and reported traces order should match.
				if r.reportedTraces[idx] != trace {
					t.Fatalf("Expected trace 0x%x, got 0x%x",
						trace.traceHash, r.reportedTraces[idx].traceHash)
				}
			}
			for _, expCount := range test.expectedCounts {
				// Expected and reported count order doesn't necessarily match.
				found := false
				for _, repCount := range r.reportedCounts {
					if expCount == repCount {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("Expected count %d for trace 0x%x not found",
						expCount.count, expCount.traceHash)
				}
			}
		})
	}
}
