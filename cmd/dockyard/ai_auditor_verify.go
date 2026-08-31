package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
)

func verifyAIAuditorRuns(arguments []string, input io.Reader) error {
	flags := flag.NewFlagSet("verify-ai-auditor-runs", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	controlPlaneURL := flags.String("control-plane-url", "", "control-plane HTTP(S) origin")
	sinceValue := flags.String("since", "", "earliest accepted run start in RFC3339")
	timeout := flags.Duration("timeout", 15*time.Minute, "maximum verification time")
	pollInterval := flags.Duration("poll-interval", 2*time.Second, "interval between checks")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *controlPlaneURL == "" || *sinceValue == "" {
		return errors.New("usage: dockyard verify-ai-auditor-runs --control-plane-url URL --since RFC3339 [--timeout DURATION] [--poll-interval DURATION] < TOKEN")
	}
	if *timeout <= 0 || *timeout > time.Hour || *pollInterval <= 0 || *pollInterval > *timeout {
		return errors.New("verification timeout must be at most one hour and poll interval must be positive and no longer than the timeout")
	}
	endpoint, err := normalizedAuditorEndpoint("control-plane URL", *controlPlaneURL, false)
	if err != nil {
		return err
	}
	since, err := time.Parse(time.RFC3339, *sinceValue)
	if err != nil {
		return errors.New("--since must be an RFC3339 timestamp")
	}
	tokenData, err := io.ReadAll(io.LimitReader(input, maxAuditorSecretBytes+1))
	if err != nil {
		return fmt.Errorf("read auditor token: %w", err)
	}
	if len(tokenData) > maxAuditorSecretBytes || strings.TrimSpace(string(tokenData)) == "" || strings.ContainsAny(string(tokenData), "\r\n") {
		return errors.New("auditor token must contain one value between 1 and 16384 bytes without line breaks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	err = waitForAIAuditorRuns(ctx, auditorHTTPClient(nil), endpoint, string(tokenData), since, *pollInterval)
	if err != nil {
		return err
	}
	fmt.Println("Fresh completed security-auditor and reliability-auditor runs verified.")
	return nil
}

func waitForAIAuditorRuns(ctx context.Context, client *http.Client, endpoint, token string, since time.Time, pollInterval time.Duration) error {
	required := map[string]bool{"security-auditor": false, "reliability-auditor": false}
	for {
		var response struct {
			Items []store.AIAuditRun `json:"items"`
		}
		err := auditorRequest(ctx, client, auditorConfig{DockyardURL: endpoint, DockyardToken: token}, http.MethodGet, "/v1/ai/audit-runs/self", nil, &response)
		if err == nil {
			for _, run := range response.Items {
				if run.Status == "completed" && !run.StartedAt.Before(since) {
					if _, ok := required[run.AgentName]; ok {
						required[run.AgentName] = true
					}
				}
			}
			if required["security-auditor"] && required["reliability-auditor"] {
				return nil
			}
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			missing := make([]string, 0, 2)
			for _, name := range []string{"security-auditor", "reliability-auditor"} {
				if !required[name] {
					missing = append(missing, name)
				}
			}
			return fmt.Errorf("fresh completed audit runs not observed for %s before timeout: %w", strings.Join(missing, ", "), ctx.Err())
		case <-timer.C:
		}
	}
}
