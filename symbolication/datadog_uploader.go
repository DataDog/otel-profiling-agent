package symbolication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/DataDog/zstd"
	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/vc"
)

const binaryCacheSize = 1000

const sourceMapEndpoint = "/api/v2/srcmap"

const symbolCopyTimeout = 10 * time.Second
const uploadTimeout = 15 * time.Second

type DatadogUploader struct {
	ddAPIKey  string
	intakeURL string
	dryRun    bool

	uploadCache *lru.SyncedLRU[libpf.FileID, struct{}]
	client      *http.Client
}

var _ Uploader = (*DatadogUploader)(nil)

func NewDatadogUploader() (Uploader, error) {
	err := exec.Command("objcopy", "--version").Run()
	if err != nil {
		return nil, fmt.Errorf("objcopy is not available: %w", err)
	}

	ddAPIKey := os.Getenv("DD_API_KEY")
	if ddAPIKey == "" {
		return nil, errors.New("DD_API_KEY is not set")
	}

	ddSite := os.Getenv("DD_SITE")
	if ddSite == "" {
		return nil, errors.New("DD_SITE is not set")
	}

	intakeURL, err := url.JoinPath("https://sourcemap-intake."+ddSite, sourceMapEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	dryRun := os.Getenv("DD_EXPERIMENTAL_LOCAL_SYMBOL_UPLOAD_DRY_RUN") == "true"

	uploadCache, err := lru.NewSynced[libpf.FileID, struct{}](binaryCacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	return &DatadogUploader{
		ddAPIKey:  ddAPIKey,
		intakeURL: intakeURL,
		dryRun:    dryRun,

		uploadCache: uploadCache,
		client: &http.Client{
			Timeout: uploadTimeout,
		},
	}, nil
}

func (d *DatadogUploader) HandleExecutable(elfRef *pfelf.Reference, fileID libpf.FileID) {
	_, ok := d.uploadCache.Peek(fileID)
	if ok {
		log.Debugf("Skipping symbol upload for executable %s: already uploaded",
			elfRef.FileName())
		return
	}
	fileName := elfRef.FileName()

	ef, err := elfRef.GetELF()
	// If the ELF file is not found, we ignore it
	// This can happen for short-lived processes that are already gone by the time
	// we try to upload symbols
	if err != nil {
		log.Debugf("Skipping symbol upload for executable %s: %v",
			fileName, err)
		return
	}

	// This needs to be done synchronously before the process manager closes the elfRef
	inputFilePath := localDebugSymbolsPath(ef, elfRef)
	if inputFilePath == "" {
		log.Debugf("Skipping symbol upload for executable %s: no debug symbols found", fileName)
		return
	}

	e := newExecutableMetadata(fileName, ef, fileID)

	d.uploadCache.Add(fileID, struct{}{})
	// TODO:
	// This will launch a goroutine to upload the symbols, per executable
	// which would potentially lead to a large number of goroutines
	// if there are many executables.
	// Ideally, we should limit the number of concurrent uploads
	go func() {
		_, err = os.Stat(inputFilePath)
		if err != nil {
			d.uploadCache.Remove(fileID)
			log.Debugf("Skipping symbol extraction for short-lived executable %s: %v", fileName,
				err)
			return
		}

		if d.dryRun {
			log.Infof("Dry run: would upload symbols %s for executable: %s", inputFilePath, e)
			return
		}

		err = d.handleSymbols(inputFilePath, e)
		if err != nil {
			d.uploadCache.Remove(fileID)
			log.Errorf("Failed to handle symbols: %v for executable: %s", err, e)
		} else {
			log.Infof("Symbols uploaded successfully for executable: %s", e)
		}
	}()
}

type executableMetadata struct {
	Arch          string `json:"arch"`
	GNUBuildID    string `json:"gnu_build_id"`
	GoBuildID     string `json:"go_build_id"`
	FileHash      string `json:"file_hash"`
	Type          string `json:"type"`
	SymbolSource  string `json:"symbol_source"`
	Origin        string `json:"origin"`
	OriginVersion string `json:"origin_version"`
	FileName      string `json:"filename"`

	filePath string
}

func newExecutableMetadata(fileName string, elf *pfelf.File,
	fileID libpf.FileID) *executableMetadata {
	isGolang := elf.IsGolang()

	buildID, err := elf.GetBuildID()
	if err != nil {
		log.Debugf(
			"Unable to get GNU build ID for executable %s: %s", fileName, err)
	}

	goBuildID := ""
	if isGolang {
		goBuildID, err = elf.GetGoBuildID()
		if err != nil {
			log.Debugf(
				"Unable to get Go build ID for executable %s: %s", fileName, err)
		}
	}

	return &executableMetadata{
		Arch:          runtime.GOARCH,
		GNUBuildID:    buildID,
		GoBuildID:     goBuildID,
		FileHash:      fileID.StringNoQuotes(),
		Type:          "elf_symbol_file",
		Origin:        "otel-profiling-agent",
		OriginVersion: strings.TrimLeft(vc.Version(), "v"),
		SymbolSource:  "debug_info",
		FileName:      filepath.Base(fileName),
		filePath:      fileName,
	}
}

func (e *executableMetadata) String() string {
	return fmt.Sprintf(
		"%s, filename=%s, arch=%s, gnu_build_id=%s, go_build_id=%s, file_hash=%s, type=%s"+
			", symbol_source=%s, origin=%s, origin_version=%s",
		e.filePath, e.FileName, e.Arch, e.GNUBuildID, e.GoBuildID, e.FileHash, e.Type,
		e.SymbolSource, e.Origin, e.OriginVersion,
	)
}

func (d *DatadogUploader) handleSymbols(symbolPath string,
	e *executableMetadata) error {
	symbolFile, err := os.CreateTemp("", "objcopy-debug")
	if err != nil {
		return fmt.Errorf("failed to create temp file to extract symbols: %w", err)
	}
	defer os.Remove(symbolFile.Name())
	defer symbolFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), symbolCopyTimeout)
	defer cancel()
	err = d.copySymbols(ctx, symbolPath, symbolFile.Name())
	if err != nil {
		return fmt.Errorf("failed to copy symbols: %w", err)
	}

	err = d.uploadSymbols(symbolFile, e)
	if err != nil {
		return fmt.Errorf("failed to upload symbols: %w", err)
	}

	return nil
}

func (d *DatadogUploader) copySymbols(ctx context.Context, inputPath, outputPath string) error {
	args := []string{
		"--only-keep-debug",
		"--remove-section=.gdb_index",
		inputPath,
		outputPath,
	}
	_, err := exec.CommandContext(ctx, "objcopy", args...).Output()
	if err != nil {
		return fmt.Errorf("failed to extract debug symbols: %w", cleanCmdError(err))
	}
	return nil
}

func (d *DatadogUploader) uploadSymbols(symbolFile *os.File,
	e *executableMetadata) error {
	req, err := d.buildSymbolUploadRequest(symbolFile, e)
	if err != nil {
		return fmt.Errorf("failed to build symbol upload request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("error while uploading symbols: %s, %s", resp.Status, string(respBody))
	}

	return nil
}

func (d *DatadogUploader) buildSymbolUploadRequest(symbolFile *os.File,
	e *executableMetadata) (*http.Request, error) {
	b := new(bytes.Buffer)

	compressed := zstd.NewWriter(b)

	mw := multipart.NewWriter(compressed)

	// Copy the symbol file into the multipart writer
	filePart, err := mw.CreateFormFile("elf_symbol_file", "elf_symbol_file")
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	_, err = io.Copy(filePart, symbolFile)
	if err != nil {
		return nil, fmt.Errorf("failed to copy symbol file: %w", err)
	}

	// Write the event metadata into the multipart writer
	eventPart, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{`form-data; name="event"; filename="event.json"`},
		"Content-Type":        []string{"application/json"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create event part: %w", err)
	}

	err = json.NewEncoder(eventPart).Encode(e)
	if err != nil {
		return nil, fmt.Errorf("failed to write JSON metadata: %w", err)
	}

	// Close the multipart writer then the zstd writer
	err = mw.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	err = compressed.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close zstd writer: %w", err)
	}

	r, err := http.NewRequest(http.MethodPost, d.intakeURL, b)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	r.Header.Set("Dd-Api-Key", d.ddAPIKey)
	r.Header.Set("Dd-Evp-Origin", "otel-profiling-agent")
	r.Header.Set("Dd-Evp-Origin-Version", vc.Version())
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Content-Encoding", "zstd")
	return r, nil
}

// localDebugSymbolsPath returns the path to the local debug symbols for the given ELF file.
func localDebugSymbolsPath(ef *pfelf.File, elfRef *pfelf.Reference) string {
	fileName := elfRef.FileName()

	filePath, err := debugSymbolsPathForElf(ef, fileName)
	if err != nil {
		log.Debugf("ELF symbols not found in %s: %v", fileName, err)
	} else {
		return filePath
	}

	// Check if there is a separate debug ELF file for this executable
	// following the same order as GDB
	// https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html

	// First, check based on the GNU build ID
	debugElf, debugFile := ef.OpenDebugBuildID(elfRef)
	if debugElf != nil {
		filePath, err = debugSymbolsPathForElf(debugElf, debugFile)
		if err != nil {
			log.Debugf("ELF symbols not found in %s: %v", debugFile, err)
		} else {
			return filePath
		}
	}

	// Then, check based on the debug link
	debugElf, debugFile = ef.OpenDebugLink(elfRef.FileName(), elfRef)

	if debugElf != nil {
		filePath, err = debugSymbolsPathForElf(debugElf, debugFile)
		if err != nil {
			log.Debugf("ELF symbols not found in %s: %v", debugFile, err)
		} else {
			return filePath
		}
	}

	return ""
}

func debugSymbolsPathForElf(ef *pfelf.File, fileName string) (string, error) {
	filePath, err := ef.FilePath()
	if err != nil {
		return "", fmt.Errorf("failed to get ELF file path for executable %s: %v", fileName, err)
	}
	if !ef.HasDWARFData() {
		return "", fmt.Errorf("executable %s does not have DWARF data", fileName)
	}
	return filePath, nil
}

// cleanCmdError simplifies error messages from os/exec.Cmd.Run.
// For ExitErrors, it trims and returns stderr. By default, ExitError prints the exit
// status but not stderr.
//
// cleanCmdError returns other errors unmodified.
func cleanCmdError(err error) error {
	var xerr *exec.ExitError
	if errors.As(err, &xerr) {
		if stderr := strings.TrimSpace(string(xerr.Stderr)); stderr != "" {
			return fmt.Errorf("%w: %s", err, stderr)
		}
	}
	return err
}
