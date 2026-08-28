// Package databaseplugin defines the versioned process protocol used by
// out-of-tree Dockyard database drivers.
package databaseplugin

import (
	"encoding/json"
	"errors"
	"io"
)

const ProtocolVersion = 1

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
	var request Request
	if err := json.NewDecoder(io.LimitReader(input, 4<<20)).Decode(&request); err != nil {
		return err
	}
	response := Response{ProtocolVersion: ProtocolVersion}
	if request.ProtocolVersion != ProtocolVersion {
		response.Error = "unsupported protocol version"
	} else {
		var err error
		switch request.Operation {
		case "describe":
			description := driver.Describe()
			response.Description = &description
		case "render":
			if request.Render == nil {
				err = errors.New("render request is required")
			} else {
				result, callErr := driver.Render(*request.Render)
				response.Result, err = &result, callErr
			}
		case "backup":
			if request.Utility == nil {
				err = errors.New("utility request is required")
			} else {
				plan, callErr := driver.Backup(*request.Utility)
				response.Plan, err = &plan, callErr
			}
		case "restore":
			if request.Utility == nil {
				err = errors.New("utility request is required")
			} else {
				plan, callErr := driver.Restore(*request.Utility)
				response.Plan, err = &plan, callErr
			}
		case "readiness":
			if request.Utility == nil {
				err = errors.New("utility request is required")
			} else {
				plan, callErr := driver.Readiness(*request.Utility)
				response.Plan, err = &plan, callErr
			}
		default:
			err = errors.New("unsupported operation")
		}
		if err != nil {
			response.Error = err.Error()
			response.Result, response.Plan = nil, nil
		}
	}
	return json.NewEncoder(output).Encode(response)
}
