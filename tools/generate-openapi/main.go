package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var routePattern = regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE) (/[^" ]+)"`)
var parameterPattern = regexp.MustCompile(`\{([^}]+)\}`)

type operation struct{ method, path string }

func main() {
	root, err := repositoryRoot()
	if err != nil {
		panic(err)
	}
	files := []string{"server.go", "clusters.go"}
	byPath := map[string][]operation{}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, "internal", "httpapi", name))
		if err != nil {
			panic(err)
		}
		for _, match := range routePattern.FindAllSubmatch(data, -1) {
			op := operation{method: strings.ToLower(string(match[1])), path: string(match[2])}
			if !isAPIPath(op.path) {
				continue
			}
			byPath[op.path] = append(byPath[op.path], op)
		}
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var output bytes.Buffer
	output.WriteString(`openapi: 3.1.0
info:
  title: Dockyard API
  version: 0.1.0
  description: Generated route contract for the Dockyard Compose-on-Swarm control plane.
servers:
  - url: http://localhost:8080
security:
  - bearerAuth: []
paths:
`)
	for _, path := range paths {
		fmt.Fprintf(&output, "  %s:\n", path)
		operations := byPath[path]
		sort.Slice(operations, func(i, j int) bool { return operations[i].method < operations[j].method })
		for _, op := range operations {
			fmt.Fprintf(&output, "    %s:\n      operationId: %s\n      tags: [%s]\n", op.method, operationID(op), tag(op.path))
			if isPublic(op.path) {
				output.WriteString("      security: []\n")
			} else if strings.HasPrefix(op.path, "/v1/agent/") {
				output.WriteString("      security:\n        - mutualTLS: []\n")
			}
			parameters := parameterPattern.FindAllStringSubmatch(op.path, -1)
			if len(parameters) > 0 {
				output.WriteString("      parameters:\n")
				for _, parameter := range parameters {
					format := ""
					if parameter[1] != "token" {
						format = "\n            format: uuid"
					}
					fmt.Fprintf(&output, "        - name: %s\n          in: path\n          required: true\n          schema:\n            type: string%s\n", parameter[1], format)
				}
			}
			if op.method == "post" || op.method == "put" || op.method == "patch" {
				if strings.HasSuffix(op.path, "/artifact-source") {
					output.WriteString("      requestBody:\n        required: true\n        content:\n          multipart/form-data:\n            schema:\n              type: object\n              required: [file]\n              properties:\n                file:\n                  type: string\n                  format: binary\n")
				} else {
					output.WriteString("      requestBody:\n        required: false\n        content:\n          application/json:\n            schema:\n              type: object\n              additionalProperties: true\n")
				}
			}
			output.WriteString("      responses:\n        '2XX':\n          description: Successful response\n        default:\n          description: Structured API error\n          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/ErrorEnvelope'\n")
		}
	}
	output.WriteString(`components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
    mutualTLS:
      type: mutualTLS
  schemas:
    ErrorEnvelope:
      type: object
      required: [error]
      properties:
        error:
          type: object
          required: [code, message]
          properties:
            code: {type: string}
            message: {type: string}
`)
	directory := filepath.Join(root, "api")
	if err := os.MkdirAll(directory, 0755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "openapi.yaml"), output.Bytes(), 0644); err != nil {
		panic(err)
	}
}

func isAPIPath(path string) bool {
	return path == "/healthz" || path == "/metrics" || strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/scim/")
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("go.mod not found")
		}
		directory = parent
	}
}

func operationID(op operation) string {
	value := op.method + "_" + strings.Trim(op.path, "/")
	value = strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_").Replace(value)
	return value
}

func tag(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 1 && parts[0] == "v1" {
		return parts[1]
	}
	return parts[0]
}

func isPublic(path string) bool {
	if path == "/healthz" || path == "/v1/auth/bootstrap" || path == "/v1/auth/login" || path == "/v1/agent/enroll" {
		return true
	}
	return strings.HasPrefix(path, "/v1/auth/sso/") || strings.HasPrefix(path, "/v1/auth/saml/") || strings.HasPrefix(path, "/v1/hooks/")
}
