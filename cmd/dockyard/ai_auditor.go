package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type auditorConfig struct {
	DockyardURL, DockyardToken, ModelURL, ModelToken, Model, AgentName, AgentVersion, Focus string
	Interval                                                                                time.Duration
}
type modelFinding struct {
	Severity     string         `json:"severity"`
	Category     string         `json:"category"`
	Title        string         `json:"title"`
	Description  string         `json:"description"`
	ResourceType string         `json:"resourceType"`
	ResourceID   string         `json:"resourceId"`
	Evidence     map[string]any `json:"evidence"`
	Remediation  string         `json:"remediation"`
}
type modelReport struct {
	Summary  string         `json:"summary"`
	Findings []modelFinding `json:"findings"`
}

func runAIAuditor() error {
	interval, err := time.ParseDuration(envDefault("DOCKYARD_AI_AUDIT_INTERVAL", "24h"))
	if err != nil || interval < time.Minute {
		return errors.New("DOCKYARD_AI_AUDIT_INTERVAL must be at least one minute")
	}
	cfg := auditorConfig{DockyardURL: strings.TrimRight(os.Getenv("DOCKYARD_CONTROL_PLANE_URL"), "/"), DockyardToken: secretValue("DOCKYARD_AI_AUDITOR_TOKEN"), ModelURL: strings.TrimRight(os.Getenv("DOCKYARD_AI_BASE_URL"), "/"), ModelToken: secretValue("DOCKYARD_AI_API_KEY"), Model: os.Getenv("DOCKYARD_AI_MODEL"), AgentName: envDefault("DOCKYARD_AI_AGENT_NAME", "dockyard-auditor"), AgentVersion: version, Focus: envDefault("DOCKYARD_AI_AUDIT_FOCUS", "security, availability, backups, failed operations, and anomalous audit activity"), Interval: interval}
	if cfg.DockyardURL == "" || cfg.DockyardToken == "" || cfg.ModelURL == "" || cfg.Model == "" {
		return errors.New("control-plane URL, auditor token, AI base URL, and model are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	client := &http.Client{Timeout: 2 * time.Minute}
	for {
		if err = performAIAudit(ctx, client, cfg); err != nil {
			slog.Error("AI audit failed", "error", err)
		} else {
			slog.Info("AI audit completed")
		}
		timer := time.NewTimer(cfg.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func secretValue(name string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	file := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if file == "" {
		return ""
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func performAIAudit(ctx context.Context, client *http.Client, cfg auditorConfig) error {
	var snapshot json.RawMessage
	if err := auditorRequest(ctx, client, cfg, http.MethodGet, "/v1/ai/audit-snapshot", nil, &snapshot); err != nil {
		return err
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := auditorRequest(ctx, client, cfg, http.MethodPost, "/v1/ai/audit-runs", map[string]any{"agentName": cfg.AgentName, "agentVersion": cfg.AgentVersion, "model": cfg.Model, "scope": map[string]any{"kind": "platform", "focus": cfg.Focus}}, &run); err != nil {
		return err
	}
	report, err := requestAuditModel(ctx, client, cfg, snapshot)
	if err != nil {
		_ = auditorRequest(ctx, client, cfg, http.MethodPatch, "/v1/ai/audit-runs/"+run.ID, map[string]string{"status": "failed", "summary": err.Error()}, nil)
		return err
	}
	for _, finding := range report.Findings {
		if err = auditorRequest(ctx, client, cfg, http.MethodPost, "/v1/ai/audit-runs/"+run.ID+"/findings", finding, nil); err != nil {
			_ = auditorRequest(ctx, client, cfg, http.MethodPatch, "/v1/ai/audit-runs/"+run.ID, map[string]string{"status": "failed", "summary": err.Error()}, nil)
			return err
		}
	}
	return auditorRequest(ctx, client, cfg, http.MethodPatch, "/v1/ai/audit-runs/"+run.ID, map[string]string{"status": "completed", "summary": report.Summary}, nil)
}

func auditorRequest(ctx context.Context, client *http.Client, cfg auditorConfig, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, cfg.DockyardURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.DockyardToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("dockyard %s returned HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if output != nil && len(data) > 0 {
		return json.Unmarshal(data, output)
	}
	return nil
}

func requestAuditModel(ctx context.Context, client *http.Client, cfg auditorConfig, snapshot json.RawMessage) (modelReport, error) {
	prompt := "You are a defensive infrastructure auditor. Analyze this secret-free Docker Swarm control-plane snapshot. Focus on: " + cfg.Focus + ". Return only JSON with summary and findings. Each finding requires severity (info|low|medium|high|critical), category, title, description, resourceType, resourceId, evidence object, and remediation. Do not invent resources or claim access to omitted data.\nSNAPSHOT:\n" + string(snapshot)
	payload := map[string]any{"model": cfg.Model, "temperature": 0, "response_format": map[string]string{"type": "json_object"}, "messages": []map[string]string{{"role": "system", "content": "Return strict JSON. Focus on availability, security, backup coverage, stale clusters, failed operations, and anomalous audit activity."}, {"role": "user", "content": prompt}}}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ModelURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return modelReport{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.ModelToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.ModelToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return modelReport{}, err
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return modelReport{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return modelReport{}, fmt.Errorf("model gateway returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(response)))
	}
	var completion struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err = json.Unmarshal(response, &completion); err != nil || len(completion.Choices) == 0 {
		return modelReport{}, errors.New("model gateway returned no completion")
	}
	content := strings.TrimSpace(completion.Choices[0].Message.Content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	var report modelReport
	if err = json.Unmarshal([]byte(strings.TrimSpace(content)), &report); err != nil {
		return modelReport{}, fmt.Errorf("parse model audit report: %w", err)
	}
	return report, nil
}
