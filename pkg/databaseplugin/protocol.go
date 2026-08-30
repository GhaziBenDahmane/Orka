// Package databaseplugin defines the versioned process protocol used by
// out-of-tree Dockyard database drivers.
package databaseplugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	ProtocolVersion = 1
	MaxRequestBytes = 4 << 20
)

type Description struct {
	Name            string   `json:"name"`
	DefaultVersion  string   `json:"defaultVersion"`
	Capabilities    []string `json:"capabilities"`
	BackupExtension string   `json:"backupExtension,omitempty"`
}

type RenderRequest struct {
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Config  map[string]any `json:"config"`
}

type UtilityRequest struct {
	Version     string            `json:"version"`
	Host        string            `json:"host"`
	Credentials map[string]string `json:"credentials"`
	Filename    string            `json:"filename"`
}

type Result struct {
	ComposeYAML string            `json:"composeYaml"`
	Environment map[string]string `json:"environment"`
	Credentials map[string]string `json:"credentials"`
	InternalURL string            `json:"internalUrl"`
	Version     string            `json:"version"`
}

type Plan struct {
	Image       string            `json:"image"`
	Command     []string          `json:"command"`
	Environment map[string]string `json:"environment"`
	Extension   string            `json:"extension"`
	Files       map[string]string `json:"files,omitempty"`
}

type Request struct {
	ProtocolVersion int             `json:"protocolVersion"`
	Operation       string          `json:"operation"`
	Render          *RenderRequest  `json:"render,omitempty"`
	Utility         *UtilityRequest `json:"utility,omitempty"`
}

type Response struct {
	ProtocolVersion int          `json:"protocolVersion"`
	Description     *Description `json:"description,omitempty"`
	Result          *Result      `json:"result,omitempty"`
	Plan            *Plan        `json:"plan,omitempty"`
	Error           string       `json:"error,omitempty"`
}

type Driver interface {
	Describe() Description
	Render(RenderRequest) (Result, error)
	Backup(UtilityRequest) (Plan, error)
	Restore(UtilityRequest) (Plan, error)
	Readiness(UtilityRequest) (Plan, error)
}

// Serve handles one request on stdin and writes one response to stdout.
func Serve(driver Driver, input io.Reader, output io.Writer) error {
	request, err := decodeRequest(input)
	if err != nil {
		return err
	}
	response := Response{ProtocolVersion: ProtocolVersion}
	if request.ProtocolVersion != ProtocolVersion {
		response.Error = "unsupported protocol version"
	} else if !validRequestShape(request) {
		response.Error = "invalid request shape"
	} else {
		var callErr error
		switch request.Operation {
		case "describe":
			description := driver.Describe()
			response.Description = &description
		case "render":
			result, err := driver.Render(*request.Render)
			response.Result, callErr = &result, err
		case "backup":
			plan, err := driver.Backup(*request.Utility)
			response.Plan, callErr = &plan, err
		case "restore":
			plan, err := driver.Restore(*request.Utility)
			response.Plan, callErr = &plan, err
		case "readiness":
			plan, err := driver.Readiness(*request.Utility)
			response.Plan, callErr = &plan, err
		}
		if callErr != nil {
			response.Error = callErr.Error()
			response.Description, response.Result, response.Plan = nil, nil, nil
		}
	}
	return json.NewEncoder(output).Encode(response)
}

func decodeRequest(input io.Reader) (Request, error) {
	payload, err := io.ReadAll(io.LimitReader(input, MaxRequestBytes+1))
	if err != nil {
		return Request{}, err
	}
	if len(payload) > MaxRequestBytes {
		return Request{}, errors.New("database driver request exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var request Request
	if err = decoder.Decode(&request); err != nil {
		return Request{}, err
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("database driver request must contain one JSON value")
	}
	return request, nil
}

func validRequestShape(request Request) bool {
	switch request.Operation {
	case "describe":
		return request.Render == nil && request.Utility == nil
	case "render":
		return request.Render != nil && request.Utility == nil
	case "backup", "restore", "readiness":
		return request.Render == nil && request.Utility != nil
	default:
		return false
	}
}
