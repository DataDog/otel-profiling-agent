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

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/libpf/vc"
)

const binaryCacheSize = 1000

const sourceMapEndpoint = "/api/v2/srcmap"

type DatadogUploader struct {
	ddAPIKey  string
	intakeURL string
	dryRun    bool

	uploadCache *lru.SyncedLRU[libpf.FileID, struct{}]
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
	}, nil
}

func (d *DatadogUploader) HandleExecutable(ctx context.Context, elfRef *pfelf.Reference,
	fileID libpf.FileID) error {
	_, ok := d.uploadCache.Peek(fileID)
	if ok {
		log.Debugf("Skipping symbol upload for executable %s: already uploaded",
			elfRef.FileName())
		return nil
	}
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

	// This needs to be done synchronously before the process manager closes the elfRef
	inputFilePath := localDebugSymbolsPath(ef, elfRef)
	if inputFilePath == "" {
		log.Debugf("Skipping symbol upload for executable %s: no debug symbols found", fileName)
		return nil
	}

	e, err := newExecutableMetadata(fileName, ef, fileID)
	if err != nil {
		return err
	}


	symbolFile, err := os.CreateTemp("", "objcopy-debug")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	err = d.copySymbols(ctx, inputFilePath, symbolFile.Name())
	if err != nil {
		return fmt.Errorf("failed to copy symbols: %w", err)
	}

	d.uploadCache.Add(fileID, struct{}{})
	// TODO:
	// This will launch a goroutine to upload the symbols, per executable
	// which would potentially lead to a large number of goroutines
	// if there are many executables.
	// Ideally, we should limit the number of concurrent uploads
	go func() {
		if d.dryRun {
			log.Infof("Dry run: would upload symbols %s for executable: %s", inputFilePath, e)
			return
		}

		err = d.uploadSymbols(symbolFile, e)
		if err != nil {
			log.Errorf("Failed to upload symbols: %v for executable: %s", err, e)
			d.uploadCache.Remove(fileID)
		} else {
			log.Infof("Symbols uploaded successfully for executable: %s", e)
		}
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

func (e *executableMetadata) String() string {
	return fmt.Sprintf(
		"%s, arch=%s, gnu_build_id=%s, go_build_id=%s, file_hash=%s, platform=%s, type=%s",
		e.fileName, e.Arch, e.GNUBuildID, e.GoBuildID, e.FileHash, e.Platform, e.Type,
	)
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

func (d *DatadogUploader) uploadSymbols(symbolFile *os.File, e *executableMetadata) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := d.buildSymbolUploadRequest(ctx, symbolFile, e)
	if err != nil {
		return fmt.Errorf("failed to build symbol upload request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
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
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	r.Header.Set("DD-API-KEY", d.ddAPIKey)
	r.Header.Set("DD-EVP-ORIGIN", "otel-profiling-agent")
	r.Header.Set("DD-EVP-ORIGIN-VERSION", vc.Version())
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Content-Encoding", "gzip")
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
