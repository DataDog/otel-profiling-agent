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
	"maps"
	"net/url"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	lru "github.com/elastic/go-freelru"
	pprofile "github.com/google/pprof/profile"
	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/xsync"
	"github.com/elastic/otel-profiling-agent/util"
	"github.com/elastic/otel-profiling-agent/vc"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*DatadogReporter)(nil)

const profilerName = "dd-otel-profiling-agent"
const profilingEndPoint = "/profiling/v1/input"

// DatadogReporter receives and transforms information to be OTLP/profiles compliant.
type DatadogReporter struct {
	// client for the connection to the receiver.
	// client otlpcollector.ProfilesServiceClient

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void

	// rpcStats stores gRPC related statistics.
	rpcStats *StatsHandlerImpl

	agentAddr string

	timeline bool

	samplingPeriod uint64

	saveCPUProfile bool

	// To fill in the OTLP/profiles signal with the relevant information,
	// this structure holds in long term storage information that might
	// be duplicated in other places but not accessible for DatadogReporter.

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// fallbackSymbols keeps track of FrameID to their symbol.
	fallbackSymbols *lru.SyncedLRU[libpf.FrameID, string]

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, execInfo]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]]

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[map[traceAndMetaKey]*traceFramesCounts]

	// execPathes stores the last known execPath for a PID.
	execPathes *lru.SyncedLRU[util.PID, string]
}

// ReportTraceEvent enqueues reported trace events for the Datadog reporter.
func (r *DatadogReporter) ReportTraceEvent(trace *libpf.Trace,
	timestamp libpf.UnixTime64, comm, podName, containerID,
	containerName, apmServiceName string, pid util.PID, tid util.TID) {
	traceEvents := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&traceEvents)

	key := traceAndMetaKey{
		hash:           trace.Hash,
		comm:           comm,
		podName:        podName,
		containerID:    containerID,
		containerName:  containerName,
		apmServiceName: apmServiceName,
		pid:            pid,
		tid:            tid,
	}

	if tr, exists := (*traceEvents)[key]; exists {
		tr.timestamps = append(tr.timestamps, uint64(timestamp))
		(*traceEvents)[key] = tr
		return
	}

	(*traceEvents)[key] = &traceFramesCounts{
		files:      trace.Files,
		linenos:    trace.Linenos,
		frameTypes: trace.FrameTypes,
		timestamps: []uint64{uint64(timestamp)},
	}
}

// SupportsReportTraceEvent returns true if the reporter supports reporting trace events
// via ReportTraceEvent().
func (r *DatadogReporter) SupportsReportTraceEvent() bool {
	return true
}

// ReportFramesForTrace is a NOP for DatadogReporter.
func (r *DatadogReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP for DatadogReporter.
func (r *DatadogReporter) ReportCountForTrace(_ libpf.TraceHash, _ libpf.UnixTime64,
	_ uint16, _, _, _, _ string) {
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

func (r *DatadogReporter) ProcessMetadata(_ context.Context, pid util.PID, execPath string) {
	r.execPathes.Add(pid, execPath)
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *DatadogReporter) FrameMetadata(fileID libpf.FileID, addressOrLine libpf.AddressOrLineno,
	lineNumber util.SourceLineno, functionOffset uint32, functionName, filePath string) {
	if frameMapLock, exists := r.frames.Get(fileID); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		if filePath == "" {
			// The new filePath may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := (*frameMap)[addressOrLine]; exists {
				filePath = s.filePath
			}
		}

		(*frameMap)[addressOrLine] = sourceInfo{
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
	mu := xsync.NewRWMutex(v)
	r.frames.Add(fileID, &mu)
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
		RPCBytesOutCount:  r.rpcStats.GetRPCBytesOut(),
		RPCBytesInCount:   r.rpcStats.GetRPCBytesIn(),
		WireBytesOutCount: r.rpcStats.GetWireBytesOut(),
		WireBytesInCount:  r.rpcStats.GetWireBytesIn(),
	}
}

// StartDatadog sets up and manages the reporting connection to the Datadog Backend.
func StartDatadog(mainCtx context.Context, cfg *Config) (Reporter, error) {
	cacheSize := config.TraceCacheEntries()
	fallbackSymbols, err := lru.NewSynced[libpf.FrameID, string](cacheSize, libpf.FrameID.Hash32)
	if err != nil {
		return nil, err
	}

	executables, err := lru.NewSynced[libpf.FileID, execInfo](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	execPathes, err := lru.NewSynced[util.PID, string](cacheSize, util.PID.Hash32)
	if err != nil {
		return nil, err
	}

	// Next step: Dynamically configure the size of this LRU.
	// Currently, we use the length of the JSON array in
	// hostmetadata/hostmetadata.json.
	hostmetadata, err := lru.NewSynced[string, string](115, hashString)
	if err != nil {
		return nil, err
	}

	r := &DatadogReporter{
		stopSignal:      make(chan libpf.Void),
		rpcStats:        NewStatsHandler(),
		agentAddr:       cfg.CollAgentAddr,
		samplingPeriod:  1000000000 / uint64(cfg.SamplesPerSecond),
		saveCPUProfile:  cfg.SaveCPUProfile,
		timeline:        cfg.Timeline,
		fallbackSymbols: fallbackSymbols,
		executables:     executables,
		frames:          frames,
		hostmetadata:    hostmetadata,
		traceEvents:     xsync.NewRWMutex(map[traceAndMetaKey]*traceFramesCounts{}),
		execPathes:      execPathes,
	}

	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	go func() {
		tick := time.NewTicker(cfg.Times.ReportInterval())
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
				tick.Reset(libpf.AddJitter(cfg.Times.ReportInterval(), 0.2))
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

	customAttributes := []string{"container_id", "container_name", "thread_name", "pod_name"}
	for _, attr := range customAttributes {
		tags = append(tags, "ddprof.custom_ctx:"+attr)
	}
	// The profiler_name tag allows us to differentiate the source of the profiles.
	tags = append(tags, "runtime:native", "remote_symbols:yes",
		"profiler_name:"+profilerName,
		"profiler_version:"+vc.Version(),
		"cpu_arch:"+runtime.GOARCH,
	)
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
		time.Unix(0, int64(startTS)), time.Unix(0, int64(endTS)), profilingURL, tags)

	return err
}

func (r *DatadogReporter) processSample(sample *pprofile.Sample, profile *pprofile.Profile, traceKey traceAndMetaKey,
	traceInfo *traceFramesCounts, fileIDtoMapping map[libpf.FileID]*pprofile.Mapping,
	frameIDtoFunction map[libpf.FrameID]*pprofile.Function,
	funcMap map[funcInfo]*pprofile.Function) {
	const unknownStr = "UNKNOWN"
	// Walk every frame of the trace.
	for i := range traceInfo.frameTypes {
		loc := createPProfLocation(profile, uint64(traceInfo.linenos[i]))

		switch frameKind := traceInfo.frameTypes[i]; frameKind {
		case libpf.NativeFrame:
			// As native frames are resolved in the backend, we use Mapping to
			// report these frames.

			if tmpMapping, exists := fileIDtoMapping[traceInfo.files[i]]; exists {
				loc.Mapping = tmpMapping
			} else {
				executionInfo, exists := r.executables.Get(traceInfo.files[i])

				// Next step: Select a proper default value,
				// if the name of the executable is not known yet.
				var fileName = unknownStr
				var buildID = traceInfo.files[i].StringNoQuotes()
				if exists {
					fileName = executionInfo.fileName
					if executionInfo.buildID != "" {
						buildID = executionInfo.buildID
					}
				}

				tmpMapping := createPprofMapping(profile, uint64(traceInfo.linenos[i]),
					fileName, buildID)
				fileIDtoMapping[traceInfo.files[i]] = tmpMapping
				loc.Mapping = tmpMapping
			}
			line := pprofile.Line{Function: createPprofFunctionEntry(funcMap, profile, "",
				loc.Mapping.File)}
			loc.Line = append(loc.Line, line)
		case libpf.KernelFrame:
			// Reconstruct frameID
			frameID := libpf.NewFrameID(traceInfo.files[i], traceInfo.linenos[i])
			// Store Kernel frame information as Line message:
			line := pprofile.Line{}

			if tmpFunction, exists := frameIDtoFunction[frameID]; exists {
				line.Function = tmpFunction
			} else {
				symbol, exists := r.fallbackSymbols.Get(frameID)
				if !exists {
					// TODO: choose a proper default value if the kernel symbol was not
					// reported yet.
					symbol = unknownStr
				}
				line.Function = createPprofFunctionEntry(
					funcMap, profile, symbol, "")
			}
			loc.Line = append(loc.Line, line)

			// To be compliant with the protocol generate a dummy mapping entry.
			loc.Mapping = getDummyMapping(fileIDtoMapping, profile,
				traceInfo.files[i])

		case libpf.AbortFrame:
			// Next step: Figure out how the OTLP protocol
			// could handle artificial frames, like AbortFrame,
			// that are not originate from a native or interpreted
			// program.
		default:
			// Store interpreted frame information as Line message:
			line := pprofile.Line{}

			fileIDInfoLock, exists := r.frames.Get(traceInfo.files[i])
			if !exists {
				// At this point, we do not have enough information for the frame.
				// Therefore, we report a dummy entry and use the interpreter as filename.
				line.Function = createPprofFunctionEntry(funcMap, profile,
					"UNREPORTED", frameKind.String())
			} else {
				fileIDInfo := fileIDInfoLock.RLock()
				si, exists := (*fileIDInfo)[traceInfo.linenos[i]]
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
				fileIDInfoLock.RUnlock(&fileIDInfo)
			}
			loc.Line = append(loc.Line, line)

			// To be compliant with the protocol generate a dummy mapping entry.
			loc.Mapping = getDummyMapping(fileIDtoMapping, profile, traceInfo.files[i])
		}
		sample.Location = append(sample.Location, loc)
	}

	execPath, _ := r.execPathes.Get(traceKey.pid)
	baseExec := path.Base(execPath)
	if baseExec == "." || baseExec == "/" {
		baseExec = execPath // avoids kernel being transformed in .
	}
	// Check if the last frame is a kernel frame.
	if len(traceInfo.frameTypes) > 0 &&
		traceInfo.frameTypes[len(traceInfo.frameTypes)-1] == libpf.KernelFrame {
		// If the last frame is a kernel frame, we need to add a dummy
		// location with the kernel as the function name.
		execPath = "kernel"
	}

	if execPath != "" {
		loc := createPProfLocation(profile, 0)
		m := createPprofFunctionEntry(funcMap, profile, baseExec, execPath)
		loc.Line = append(loc.Line, pprofile.Line{Function: m})
		sample.Location = append(sample.Location, loc)
	}

	sample.Label = make(map[string][]string)
	addTraceLabels(sample.Label, traceKey, baseExec)
	if r.timeline {
		timestamps := make([]string, 0, len(traceInfo.timestamps))
		for _, ts := range traceInfo.timestamps {
			timestamps = append(timestamps, strconv.FormatUint(ts, 10))
		}
		// Assign all timestamps as a single label entry
		sample.Label["end_timestamp_ns"] = timestamps
	}
	count := len(traceInfo.timestamps)
	sample.Value = append(sample.Value, int64(count), int64(count)*int64(r.samplingPeriod))
	profile.Sample = append(profile.Sample, sample)
}

// getPprofProfile returns a pprof profile containing all collected samples up to this moment.
func (r *DatadogReporter) getPprofProfile() (profile *pprofile.Profile,
	startTS uint64, endTS uint64) {
	traceEvents := r.traceEvents.WLock()
	samples := maps.Clone(*traceEvents)
	for key := range *traceEvents {
		delete(*traceEvents, key)
	}
	r.traceEvents.WUnlock(&traceEvents)
	numSamples := len(samples)
	if r.timeline {
		numSamples *= 4
	}

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]*pprofile.Function)

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

	for traceKey, traceInfo := range samples {

		for _, ts := range traceInfo.timestamps {
			if ts < startTS || startTS == 0 {
				startTS = ts
				continue
			}
			if ts > endTS {
				endTS = ts
			}
		}
		sample := &pprofile.Sample{}
		count := len(traceInfo.timestamps)
		r.processSample(sample, profile, traceKey, traceInfo, fileIDtoMapping,
			frameIDtoFunction, funcMap)
		totalSampleCount += count
	}
	log.Infof("Reporting pprof profile with %d samples from %v to %v",
		totalSampleCount, startTS, endTS)

	profile.DurationNanos = int64(endTS - startTS)
	profile.TimeNanos = int64(startTS)

	profile = profile.Compact()

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

//nolint:gocritic
func addTraceLabels(labels map[string][]string, k traceAndMetaKey, baseExec string) {
	if k.comm != "" {
		labels["thread_name"] = append(labels["thread_name"], k.comm)
	}

	if k.podName != "" {
		labels["pod_name"] = append(labels["pod_name"], k.podName)
	}

	if k.containerID != "" {
		labels["container_id"] = append(labels["container_id"], k.containerID)
	}

	if k.containerName != "" {
		labels["container_name"] = append(labels["container_name"], k.containerName)
	}

	if k.apmServiceName != "" {
		labels["apmServiceName"] = append(labels["apmServiceName"], k.apmServiceName)
	}

	if k.pid != 0 {
		labels["process_id"] = append(labels["process_id"], fmt.Sprintf("%d", k.pid))
	}

	if k.tid != 0 {
		// The naming has an impact on the backend side,
		// this is why we use "thread id" instead of "thread_id"
		// This is also consistent with ddprof.
		labels["thread id"] = append(labels["thread id"], fmt.Sprintf("%d", k.tid))
	}

	if baseExec != "" {
		labels["process_name"] = append(labels["process_name"], baseExec)
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
