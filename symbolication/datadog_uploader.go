package symbolication

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/libpf/vc"
)

const sourceMapEndpoint = "/api/v2/srcmap"

type DatadogUploader struct {
	ddAPIKey  string
	intakeURL string
}

var _ Uploader = (*DatadogUploader)(nil)

func NewDatadogUploader() (Uploader, error) {
	err := exec.Command("objcopy", "--version").Run()
	if err != nil {
		return nil, fmt.Errorf("objcopy is not available: %w", err)
	}

	ddAPIKey := os.Getenv("DD_API_KEY")
	if ddAPIKey == "" {
		return nil, fmt.Errorf("DD_API_KEY is not set")
	}

	ddSite := os.Getenv("DD_SITE")
	if ddSite == "" {
		return nil, fmt.Errorf("DD_SITE is not set")
	}

	intakeURL, err := url.JoinPath("https://sourcemap-intake."+ddSite, sourceMapEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	return &DatadogUploader{
		ddAPIKey:  ddAPIKey,
		intakeURL: intakeURL,
	}, nil
}

func (d *DatadogUploader) HandleExecutable(ctx context.Context, elfRef *pfelf.Reference,
	fileID libpf.FileID) error {
	fileName := elfRef.FileName()
	ef, err := elfRef.GetELF()
	// If the ELF file is not found, we ignore it
	// This can happen for short-lived processes that are already gone by the time
	// we try to upload symbols
	if err != nil {
		log.Debugf("Skipping symbol upload for executable %s: %v",
			fileName, err)
		return nil
	}

	// We only upload symbols for executables that have DWARF data
	if !ef.HasDWARFData() {
		log.Debugf("Skipping symbol upload for executable %s as it does not have DWARF data",
			fileName)
		return nil
	}

	e, err := newExecutableMetadata(fileName, ef, fileID)
	if err != nil {
		return err
	}

	inputFilePath, err := ef.FilePath()
	if err != nil {
		return fmt.Errorf("failed to get ELF file path: %w", err)
	}

	symbolFile, err := os.CreateTemp("", "objcopy-debug")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	err = d.copySymbols(ctx, inputFilePath, symbolFile.Name())
	if err != nil {
		return fmt.Errorf("failed to copy symbols: %w", err)
	}

	// TODO:
	// This will launch a goroutine to upload the symbols, per executable
	// which would potentially lead to a large number of goroutines
	// if there are many executables.
	// Ideally, we should limit the number of concurrent uploads
	go func() {
		d.uploadSymbols(symbolFile, e)
		symbolFile.Close()
		os.Remove(symbolFile.Name())
	}()

	return nil
}

type executableMetadata struct {
	Arch       string `json:"arch"`
	GNUBuildID string `json:"gnu_build_id"`
	GoBuildID  string `json:"go_build_id"`
	FileHash   string `json:"file_hash"`
	Platform   string `json:"platform"`
	Type       string `json:"type"`

	fileName string
}

func newExecutableMetadata(fileName string, elf *pfelf.File,
	fileID libpf.FileID) (*executableMetadata, error) {
	buildID, err := elf.GetBuildID()
	if err != nil {
		return nil, fmt.Errorf("failed to get build id: %w", err)
	}

	goBuildID := ""
	if elf.IsGolang() {
		goBuildID, err = elf.GetGoBuildID()
		if err != nil {
			return nil, fmt.Errorf("failed to get go build id: %w", err)
		}
	}

	return &executableMetadata{
		Arch:       runtime.GOARCH,
		GNUBuildID: buildID,
		GoBuildID:  goBuildID,
		FileHash:   fileID.StringNoQuotes(),
		Platform:   "elf",
		Type:       "elf_symbol_file",

		fileName: fileName,
	}, nil
}

func (d *DatadogUploader) copySymbols(ctx context.Context, inputPath, outputPath string) error {
	args := []string{
		"--only-keep-debug",
		"--remove-section=.gdb_index",
		inputPath,
		outputPath,
	}
	err := exec.CommandContext(ctx, "objcopy", args...).Run()
	if err != nil {
		return fmt.Errorf("failed to extract debug symbols: %w", err)
	}
	return nil
}

func (d *DatadogUploader) uploadSymbols(symbolFile *os.File, e *executableMetadata) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := d.buildSymbolUploadRequest(ctx, symbolFile, e)
	if err != nil {
		log.Errorf("Failed to build symbol upload request: %v", err)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("Failed to upload symbols: %v", err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)

		log.Errorf("Failed to upload symbols: %s, %s", resp.Status, string(respBody))
		return
	}

	log.Infof("Symbols uploaded successfully for executable: %+v", e)
}

func (d *DatadogUploader) buildSymbolUploadRequest(ctx context.Context, symbolFile *os.File,
	e *executableMetadata) (*http.Request, error) {
	b := new(bytes.Buffer)

	gzipped := gzip.NewWriter(b)

	mw := multipart.NewWriter(gzipped)

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

	// Close the multipart writer then the gzip writer
	err = mw.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	err = gzipped.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, d.intakeURL, b)
	if err != nil {
		log.Error("Failed to create request", err)
		return nil, err
	}

	r.Header.Set("DD-API-KEY", d.ddAPIKey)
	r.Header.Set("DD-EVP-ORIGIN", "otel-profiling-agent")
	r.Header.Set("DD-EVP-ORIGIN-VERSION", vc.Version())
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Content-Encoding", "gzip")
	return r, nil
}
