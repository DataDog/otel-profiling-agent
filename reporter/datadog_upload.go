// simplified code from https://github.com/DataDog/dd-trace-go/blob/main/profiler/upload.go
package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

type profileData struct {
	name string
	data []byte
}

// example:
// uploadProfiles(profiles, startTime, endTime, "localhost:8126/v1/profiles")

func uploadProfiles(ctx context.Context, profiles []profileData, startTime, endTime time.Time,
	url string, tags []string) error {
	contentType, body, err := buildMultipartForm(profiles, startTime, endTime, tags)

	if err != nil {
		return err
	}

	// If you want a timeout, you can use context.WithTimeout
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)

	// If you're uploading directly to our intake, add the API key here:
	// req.Header.Set("DD-API-KEY", "xxxx")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		// Success!
		return nil
	}
	return errors.New(resp.Status)
}

type uploadEvent struct {
	Start       string   `json:"start"`
	End         string   `json:"end"`
	Attachments []string `json:"attachments"`
	Tags        string   `json:"tags_profiler"`
	Family      string   `json:"family"`
	Version     string   `json:"version"`
}

func buildMultipartForm(profiles []profileData, startTime, endTime time.Time,
	tags []string) (string, io.Reader, error) {
	var buf bytes.Buffer

	mw := multipart.NewWriter(&buf)

	event := &uploadEvent{
		Version: "4",
		Family:  "go",
		Start:   startTime.Format(time.RFC3339Nano),
		End:     endTime.Format(time.RFC3339Nano),
		Tags:    strings.Join(tags, ","),
	}

	for _, p := range profiles {
		event.Attachments = append(event.Attachments, p.name)
		f, err := mw.CreateFormFile(p.name, p.name)
		if err != nil {
			return "", nil, err
		}
		if _, err = f.Write(p.data); err != nil {
			return "", nil, err
		}
	}

	f, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{`form-data; name="event"; filename="event.json"`},
		"Content-Type":        []string{"application/json"},
	})
	if err != nil {
		return "", nil, err
	}
	if err := json.NewEncoder(f).Encode(event); err != nil {
		return "", nil, err
	}

	if err := mw.Close(); err != nil {
		return "", nil, err
	}
	return mw.FormDataContentType(), &buf, nil
}
