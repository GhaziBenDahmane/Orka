// Package composevolume extracts mounted local named volumes from Compose
// documents without depending on deployment or storage packages.
package composevolume

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Names returns declared local volume keys that are mounted by at least one
// service. Bind mounts and undeclared volume-like sources are excluded.
func Names(source string) ([]string, error) {
	var document map[string]any
	if err := yaml.Unmarshal([]byte(source), &document); err != nil {
		return nil, fmt.Errorf("parse compose yaml: %w", err)
	}
	services, ok := document["services"].(map[string]any)
	if !ok {
		return nil, errors.New("compose document must define services")
	}
	declared, ok := document["volumes"].(map[string]any)
	if document["volumes"] != nil && !ok {
		return nil, errors.New("compose volumes must be an object")
	}
	used := map[string]bool{}
	for _, rawService := range services {
		service, valid := rawService.(map[string]any)
		if !valid {
			continue
		}
		rawVolumes := service["volumes"]
		if rawVolumes == nil {
			continue
		}
		volumes, valid := rawVolumes.([]any)
		if !valid {
			return nil, errors.New("volumes must be a list")
		}
		for _, rawVolume := range volumes {
			var name string
			if spec, valid := rawVolume.(map[string]any); valid {
				kind, _ := spec["type"].(string)
				name, _ = spec["source"].(string)
				if kind != "volume" {
					continue
				}
			} else if text, valid := rawVolume.(string); valid {
				parts := strings.SplitN(text, ":", 2)
				if len(parts) != 2 {
					continue
				}
				name = parts[0]
			} else {
				return nil, errors.New("volume entries must be strings or objects")
			}
			if _, exists := declared[name]; name != "" && exists {
				used[name] = true
			}
		}
	}
	names := make([]string, 0, len(used))
	for name := range used {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
