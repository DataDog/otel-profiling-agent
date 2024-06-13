/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/elastic/otel-profiling-agent/config"

	"github.com/elastic/otel-profiling-agent/debug/log"
	"github.com/elastic/otel-profiling-agent/libpf"

	lru "github.com/elastic/go-freelru"
	pprofile "github.com/google/pprof/profile"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*DatadogReporter)(nil)

const profilingEndPoint = "/profiling/v1/input"

// DatadogReporter receives and transforms information to be OTLP/profiles compliant.
type DatadogReporter struct {
	// client for the connection to the receiver.
	// client otlpcollector.ProfilesServiceClient

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void

	// rpcStats stores gRPC related statistics.
	rpcStats *statsHandlerImpl

	agentAddr string

	samplingPeriod uint64

	saveCPUProfile bool

	// To fill in the OTLP/profiles signal with the relevant information,
	// this structure holds in long term storage information that might
	// be duplicated in other places but not accessible for DatadogReporter.

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// traces stores static information needed for samples.
	traces *lru.SyncedLRU[libpf.TraceHash, traceInfo]

	// samples holds a map of currently encountered traces.
	samples *lru.SyncedLRU[libpf.TraceHash, sample]

	// fallbackSymbols keeps track of FrameID to their symbol.
	fallbackSymbols *lru.SyncedLRU[libpf.FrameID, string]

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, execInfo]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, map[libpf.AddressOrLineno]sourceInfo]

	// execPathes stores the last known execPath for a PID.
	execPathes *lru.SyncedLRU[libpf.PID, string]
}

// ReportFramesForTrace accepts a trace with the corresponding frames
// and caches this information.
func (r *DatadogReporter) ReportFramesForTrace(trace *libpf.Trace) {
	if v, exists := r.traces.Peek(trace.Hash); exists {
		// As traces is filled from two different API endpoints,
		// some information for the trace might be available already.
		// For simplicty, the just received information overwrites the
		// the existing one.
		v.files = trace.Files
		v.linenos = trace.Linenos
		v.frameTypes = trace.FrameTypes

		r.traces.Add(trace.Hash, v)
	} else {
		r.traces.Add(trace.Hash, traceInfo{
			files:      trace.Files,
			linenos:    trace.Linenos,
			frameTypes: trace.FrameTypes,
		})
	}
}

// ReportCountForTrace accepts a hash of a trace with a corresponding count and
// caches this information.
// nolint: dupl
func (r *DatadogReporter) ReportCountForTrace(traceHash libpf.TraceHash, timestamp libpf.UnixTime32,
	count uint16, comm, podName, containerName string, pid libpf.PID) {
	if v, exists := r.traces.Peek(traceHash); exists {
		// As traces is filled from two different API endpoints,
		// some information for the trace might be available already.
		// For simplicty, the just received information overwrites the
		// the existing one.
		v.comm = comm
		v.podName = podName
		v.containerName = containerName
		v.pid = pid

		r.traces.Add(traceHash, v)
	} else {
		r.traces.Add(traceHash, traceInfo{
			comm:          comm,
			podName:       podName,
			containerName: containerName,
			pid:           pid,
		})
	}

	if v, ok := r.samples.Peek(traceHash); ok {
		v.count += uint32(count)
		v.timestamps = append(v.timestamps, uint64(timestamp))

		r.samples.Add(traceHash, v)
	} else {
		r.samples.Add(traceHash, sample{
			count:      uint32(count),
			timestamps: []uint64{uint64(timestamp)},
		})
	}
}

// ReportFallbackSymbol enqueues a fallback symbol for reporting, for a given frame.
func (r *DatadogReporter) ReportFallbackSymbol(frameID libpf.FrameID, symbol string) {
	if _, exists := r.fallbackSymbols.Peek(frameID); exists {
		return
	}
	r.fallbackSymbols.Add(frameID, symbol)
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *DatadogReporter) ExecutableMetadata(_ context.Context,
	fileID libpf.FileID, fileName, buildID string) {
	r.executables.Add(fileID, execInfo{
		fileName: fileName,
		buildID:  buildID,
	})
}

func (r *DatadogReporter) ProcessMetadata(_ context.Context, pid libpf.PID, execPath string) {
	r.execPathes.Add(pid, execPath)
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *DatadogReporter) FrameMetadata(fileID libpf.FileID, addressOrLine libpf.AddressOrLineno,
	lineNumber libpf.SourceLineno, functionOffset uint32, functionName, filePath string) {
	if v, exists := r.frames.Get(fileID); exists {
		if filePath == "" {
			// The new filePath may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := v[addressOrLine]; exists {
				filePath = s.filePath
			}
		}
		v[addressOrLine] = sourceInfo{
			lineNumber:     lineNumber,
			functionOffset: functionOffset,
			functionName:   functionName,
			filePath:       filePath,
		}
		return
	}

	v := make(map[libpf.AddressOrLineno]sourceInfo)
	v[addressOrLine] = sourceInfo{
		lineNumber:     lineNumber,
		functionOffset: functionOffset,
		functionName:   functionName,
		filePath:       filePath,
	}
	r.frames.Add(fileID, v)
}

// ReportHostMetadata enqueues host metadata.
func (r *DatadogReporter) ReportHostMetadata(metadataMap map[string]string) {
	r.addHostmetadata(metadataMap)
}

// ReportHostMetadataBlocking enqueues host metadata.
func (r *DatadogReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration) error {
	r.addHostmetadata(metadataMap)
	return nil
}

// addHostmetadata adds to and overwrites host metadata.
func (r *DatadogReporter) addHostmetadata(metadataMap map[string]string) {
	for k, v := range metadataMap {
		r.hostmetadata.Add(k, v)
	}
}

// ReportMetrics is a NOP for DatadogReporter.
func (r *DatadogReporter) ReportMetrics(_ uint32, _ []uint32, _ []int64) {}

// Stop triggers a graceful shutdown of DatadogReporter.
func (r *DatadogReporter) Stop() {
	close(r.stopSignal)
}

// GetMetrics returns internal metrics of DatadogReporter.
func (r *DatadogReporter) GetMetrics() Metrics {
	return Metrics{
		RPCBytesOutCount:  r.rpcStats.getRPCBytesOut(),
		RPCBytesInCount:   r.rpcStats.getRPCBytesIn(),
		WireBytesOutCount: r.rpcStats.getWireBytesOut(),
		WireBytesInCount:  r.rpcStats.getWireBytesIn(),
	}
}

// StartOTLP sets up and manages the reporting connection to a OTLP backend.
func StartDatadog(mainCtx context.Context, c *Config) (Reporter, error) {
	cacheSize := config.TraceCacheEntries()

	traces, err := lru.NewSynced[libpf.TraceHash, traceInfo](cacheSize, libpf.TraceHash.Hash32)
	if err != nil {
		return nil, err
	}

	samples, err := lru.NewSynced[libpf.TraceHash, sample](cacheSize, libpf.TraceHash.Hash32)
	if err != nil {
		return nil, err
	}

	fallbackSymbols, err := lru.NewSynced[libpf.FrameID, string](cacheSize, libpf.FrameID.Hash32)
	if err != nil {
		return nil, err
	}

	executables, err := lru.NewSynced[libpf.FileID, execInfo](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	frames, err := lru.NewSynced[libpf.FileID,
		map[libpf.AddressOrLineno]sourceInfo](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	execPathes, err := lru.NewSynced[libpf.PID, string](cacheSize, libpf.PID.Hash32)
	if err != nil {
		return nil, err
	}

	// Next step: Dynamically configure the size of this LRU.
	// Currently we use the length of the JSON array in
	// hostmetadata/hostmetadata.json.
	hostmetadata, err := lru.NewSynced[string, string](115, hashString)
	if err != nil {
		return nil, err
	}

	r := &DatadogReporter{
		stopSignal:      make(chan libpf.Void),
		rpcStats:        newStatsHandler(),
		agentAddr:       c.CollAgentAddr,
		samplingPeriod:  1000000000 / uint64(c.SamplesPerSecond),
		saveCPUProfile:  c.SaveCPUProfile,
		traces:          traces,
		samples:         samples,
		fallbackSymbols: fallbackSymbols,
		executables:     executables,
		frames:          frames,
		hostmetadata:    hostmetadata,
		execPathes:      execPathes,
	}

	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	go func() {
		tick := time.NewTicker(c.Times.ReportInterval())
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopSignal:
				return
			case <-tick.C:
				if err := r.reportProfile(ctx); err != nil {
					log.Errorf("Request failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(c.Times.ReportInterval(), 0.2))
			}
		}
	}()

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	// - close the gRPC connection with collection-agent
	go func() {
		<-r.stopSignal
		cancelReporting()
	}()

	return r, nil
}

// reportProfile creates and sends out a profile.
func (r *DatadogReporter) reportProfile(ctx context.Context) error {
	profile, startTS, endTS := r.getPprofProfile()

	if len(profile.Sample) == 0 {
		log.Debugf("Skip sending of pprof profile with no samples")
		return nil
	}

	// serialize the profile to a buffer and send it out
	var b bytes.Buffer
	if err := profile.Write(&b); err != nil {
		return err
	}

	if r.saveCPUProfile {
		// write profile to cpu.pprof
		f, err := os.Create("cpu.pprof")
		if err != nil {
			return err
		}
		defer f.Close()
		if err := profile.Write(f); err != nil {
			return err
		}
	}

	tags := strings.Split(config.ValidatedTags(), ";")

	customAttributes := []string{"container_name"}
	for _, attr := range customAttributes {
		tags = append(tags, fmt.Sprintf("ddprof.custom_ctx:%s", attr))
	}
	tags = append(tags, "runtime:native", fmt.Sprintf("cpu_arch:%s", runtime.GOARCH))
	foundService := false
	// check if service tag is set, if not set it to otel-profiling-agent
	for _, tag := range tags {
		if strings.HasPrefix(tag, "service:") {
			foundService = true
			break
		}
	}
	if !foundService {
		tags = append(tags, "service:otel-profiling-agent")
	}
	log.Infof("tags: %v", tags)
	profilingURL, err := url.JoinPath(r.agentAddr, profilingEndPoint)
	if err != nil {
		return err
	}
	err = uploadProfiles(ctx, []profileData{{name: "cpu.pprof", data: b.Bytes()}},
		time.Unix(int64(startTS), 0), time.Unix(int64(endTS), 0), profilingURL, tags)

	return err
}

// getProfile returns an OTLP profile containing all collected samples up to this moment.
func (r *DatadogReporter) getPprofProfile() (profile *pprofile.Profile,
	startTS uint64, endTS uint64) {
	const unkownStr = "UNKNOWN"

	// Avoid overlapping locks by copying its content.
	sampleKeys := r.samples.Keys()
	samplesCpy := make(map[libpf.TraceHash]sample, len(sampleKeys))
	for _, k := range sampleKeys {
		v, ok := r.samples.Get(k)
		if !ok {
			continue
		}
		samplesCpy[k] = v
		r.samples.Remove(k)
	}

	var samplesWoTraceinfo []libpf.TraceHash

	for trace := range samplesCpy {
		if _, exists := r.traces.Peek(trace); !exists {
			samplesWoTraceinfo = append(samplesWoTraceinfo, trace)
		}
	}

	if len(samplesWoTraceinfo) != 0 {
		log.Debugf("Missing trace information for %d samples", len(samplesWoTraceinfo))
		// Return samples for which relevant information is not available yet.
		for _, trace := range samplesWoTraceinfo {
			r.samples.Add(trace, samplesCpy[trace])
			delete(samplesCpy, trace)
		}
	}

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]*pprofile.Function)

	numSamples := len(samplesCpy)
	profile = &pprofile.Profile{
		SampleType: []*pprofile.ValueType{{Type: "cpu-samples", Unit: "count"},
			{Type: "cpu-time", Unit: "nanoseconds"}},
		Sample:            make([]*pprofile.Sample, 0, numSamples),
		PeriodType:        &pprofile.ValueType{Type: "cpu-time", Unit: "nanoseconds"},
		Period:            int64(r.samplingPeriod),
		DefaultSampleType: "cpu-time",
	}

	fileIDtoMapping := make(map[libpf.FileID]*pprofile.Mapping)
	frameIDtoFunction := make(map[libpf.FrameID]*pprofile.Function)
	totalSampleCount := 0

	for traceHash, sampleInfo := range samplesCpy {
		sample := &pprofile.Sample{}

		// Earlier we peeked into traces for traceHash and know it exists.
		trace, _ := r.traces.Get(traceHash)

		for _, ts := range sampleInfo.timestamps {
			if ts < startTS || startTS == 0 {
				startTS = ts
				continue
			}
			if ts > endTS {
				endTS = ts
			}
		}

		// Walk every frame of the trace.
		for i := range trace.frameTypes {
			loc := createPProfLocation(profile, uint64(trace.linenos[i]))

			switch frameKind := trace.frameTypes[i]; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.

				if tmpMapping, exists := fileIDtoMapping[trace.files[i]]; exists {
					loc.Mapping = tmpMapping
				} else {
					executionInfo, exists := r.executables.Get(trace.files[i])

					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					var fileName = unkownStr
					var buildID = trace.files[i].StringNoQuotes()
					if exists {
						fileName = executionInfo.fileName
						if executionInfo.buildID != "" {
							buildID = executionInfo.buildID
						}
					}

					tmpMapping := createPprofMapping(profile, uint64(trace.linenos[i]), fileName,
						buildID)
					fileIDtoMapping[trace.files[i]] = tmpMapping
					loc.Mapping = tmpMapping
				}
				line := pprofile.Line{Function: createPprofFunctionEntry(funcMap, profile, "",
					trace.comm)}
				loc.Line = append(loc.Line, line)
			case libpf.KernelFrame:
				// Reconstruct frameID
				frameID := libpf.NewFrameID(trace.files[i], trace.linenos[i])
				// Store Kernel frame information as Line message:
				line := pprofile.Line{}

				if tmpFunction, exists := frameIDtoFunction[frameID]; exists {
					line.Function = tmpFunction
				} else {
					symbol, exists := r.fallbackSymbols.Get(frameID)
					if !exists {
						// TODO: choose a proper default value if the kernel symbol was not
						// reported yet.
						symbol = unkownStr
					}
					line.Function = createPprofFunctionEntry(
						funcMap, profile, symbol, "vmlinux")
				}
				loc.Line = append(loc.Line, line)

				// To be compliant with the protocol generate a dummy mapping entry.
				loc.Mapping = getDummyMapping(fileIDtoMapping, profile,
					trace.files[i])

			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originate from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as Line message:
				line := pprofile.Line{}

				fileIDInfo, exists := r.frames.Get(trace.files[i])
				if !exists {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					line.Function = createPprofFunctionEntry(funcMap, profile,
						"UNREPORTED", frameKind.String())
				} else {
					si, exists := fileIDInfo[trace.linenos[i]]
					if !exists {
						// At this point, we do not have enough information for the frame.
						// Therefore, we report a dummy entry and use the interpreter as filename.
						// To differentiate this case with the case where no information about
						// the file ID is available at all, we use a different name for reported
						// function.
						line.Function = createPprofFunctionEntry(funcMap, profile,
							"UNRESOLVED", frameKind.String())
					} else {
						line.Line = int64(si.lineNumber)

						line.Function = createPprofFunctionEntry(funcMap, profile,
							si.functionName, si.filePath)
					}
				}
				loc.Line = append(loc.Line, line)

				// To be compliant with the protocol generate a dummy mapping entry.
				loc.Mapping = getDummyMapping(fileIDtoMapping, profile, trace.files[i])
			}
			sample.Location = append(sample.Location, loc)
		}

		execPath, _ := r.execPathes.Get(trace.pid)

		// Check if the last frame is a kernel frame.
		if trace.frameTypes[len(trace.frameTypes)-1] == libpf.KernelFrame {
			// If the last frame is a kernel frame, we need to add a dummy
			// location with the kernel as the function name.
			execPath = "kernel"
		}

		if execPath != "" {
			base := path.Base(execPath)
			loc := createPProfLocation(profile, 0)
			m := createPprofFunctionEntry(funcMap, profile, base, execPath)
			loc.Line = append(loc.Line, pprofile.Line{Function: m})
			sample.Location = append(sample.Location, loc)
		}

		sample.Label = make(map[string][]string)
		addTraceLabels(sample.Label, trace)

		count := int64(len(sampleInfo.timestamps))
		sample.Value = append(sample.Value, count, count*int64(r.samplingPeriod))
		profile.Sample = append(profile.Sample, sample)
		totalSampleCount += len(sampleInfo.timestamps)
	}
	log.Infof("Reporting pprof profile with %d samples from %v to %v",
		totalSampleCount, startTS, endTS)

	profile.DurationNanos = time.Unix(int64(endTS-startTS), 0).UnixNano()
	profile.TimeNanos = time.Unix(int64(startTS), 0).UnixNano()

	return profile, startTS, endTS
}

// createFunctionEntry adds a new function and returns its reference index.
func createPprofFunctionEntry(funcMap map[funcInfo]*pprofile.Function,
	profile *pprofile.Profile,
	name string, fileName string) *pprofile.Function {
	key := funcInfo{
		name:     name,
		fileName: fileName,
	}
	if function, exists := funcMap[key]; exists {
		return function
	}

	idx := uint64(len(profile.Function)) + 1
	function := &pprofile.Function{
		ID:       idx,
		Name:     name,
		Filename: fileName,
	}
	profile.Function = append(profile.Function, function)
	funcMap[key] = function

	return function
}

func addTraceLabels(labels map[string][]string, i traceInfo) {
	if i.comm != "" {
		labels["comm"] = append(labels["comm"], i.comm)
	}

	if i.podName != "" {
		labels["podName"] = append(labels["podName"], i.podName)
	}

	if i.containerName != "" {
		labels["container_name"] = append(labels["container_name"], i.containerName)
	}

	if i.apmServiceName != "" {
		labels["apmServiceName"] = append(labels["apmServiceName"], i.apmServiceName)
	}

	if i.pid != 0 {
		labels["process_id"] = append(labels["process_id"], fmt.Sprintf("%d", i.pid))
	}
}

// getDummyMappingIndex inserts or looks up a dummy entry for interpreted FileIDs.
func getDummyMapping(fileIDtoMapping map[libpf.FileID]*pprofile.Mapping,
	profile *pprofile.Profile, fileID libpf.FileID) *pprofile.Mapping {
	if tmpMapping, exists := fileIDtoMapping[fileID]; exists {
		return tmpMapping
	}

	mapping := createPprofMapping(profile, 0, "DUMMY", fileID.StringNoQuotes())
	fileIDtoMapping[fileID] = mapping

	return mapping
}

func createPProfLocation(profile *pprofile.Profile,
	address uint64) *pprofile.Location {
	idx := uint64(len(profile.Location)) + 1
	location := &pprofile.Location{
		ID:      idx,
		Address: address,
	}
	profile.Location = append(profile.Location, location)
	return location
}

func createPprofMapping(profile *pprofile.Profile, offset uint64,
	fileName string, buildID string) *pprofile.Mapping {
	idx := len(profile.Mapping) + 1
	mapping := &pprofile.Mapping{
		ID:      uint64(idx),
		File:    fileName,
		Offset:  offset,
		BuildID: buildID,
	}
	profile.Mapping = append(profile.Mapping, mapping)
	return mapping
}
