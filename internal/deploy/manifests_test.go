package deploy

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type deploymentManifest struct {
	Services map[string]struct {
		Command     []string          `yaml:"command"`
		Environment map[string]string `yaml:"environment"`
		Networks    []string          `yaml:"networks"`
		Secrets     []any             `yaml:"secrets"`
		Ports       []any             `yaml:"ports"`
		Volumes     []string          `yaml:"volumes"`
		ReadOnly    bool              `yaml:"read_only"`
		Tmpfs       []string          `yaml:"tmpfs"`
		CapDrop     []string          `yaml:"cap_drop"`
		SecurityOpt []string          `yaml:"security_opt"`
		StopGrace   string            `yaml:"stop_grace_period"`
		Logging     struct {
			Driver  string            `yaml:"driver"`
			Options map[string]string `yaml:"options"`
		} `yaml:"logging"`
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
		Deploy struct {
			Replicas  int               `yaml:"replicas"`
			Labels    map[string]string `yaml:"labels"`
			Resources struct {
				Limits       manifestResourceSpec `yaml:"limits"`
				Reservations manifestResourceSpec `yaml:"reservations"`
			} `yaml:"resources"`
			UpdateConfig struct {
				Order         string `yaml:"order"`
				FailureAction string `yaml:"failure_action"`
			} `yaml:"update_config"`
			RollbackConfig struct {
				Order string `yaml:"order"`
			} `yaml:"rollback_config"`
			Placement struct {
				Constraints        []string `yaml:"constraints"`
				MaxReplicasPerNode int      `yaml:"max_replicas_per_node"`
				Preferences        []struct {
					Spread string `yaml:"spread"`
				} `yaml:"preferences"`
			} `yaml:"placement"`
		} `yaml:"deploy"`
	} `yaml:"services"`
	Volumes  map[string]any `yaml:"volumes"`
	Networks map[string]struct {
		Driver     string            `yaml:"driver"`
		DriverOpts map[string]string `yaml:"driver_opts"`
	} `yaml:"networks"`
	Secrets map[string]struct {
		External bool   `yaml:"external"`
		Name     string `yaml:"name"`
	} `yaml:"secrets"`
}

type manifestResourceSpec struct {
	CPUs   string `yaml:"cpus"`
	Memory string `yaml:"memory"`
}

func readDeploymentManifest(t *testing.T, path string) deploymentManifest {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest deploymentManifest
	if err = yaml.Unmarshal(contents, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestControllerManifestHasHealthGatedRollbackUpdates(t *testing.T) {
	manifest := readDeploymentManifest(t, "../../deploy/swarm.yml")
	for _, name := range []string{"postgres", "dockyard", "traefik"} {
		service, ok := manifest.Services[name]
		if !ok {
			t.Fatalf("missing %s service", name)
		}
		if len(service.Healthcheck.Test) == 0 {
			t.Fatalf("%s has no health check", name)
		}
		if service.Deploy.Replicas != 1 || service.Deploy.UpdateConfig.FailureAction != "rollback" {
			t.Fatalf("%s rollout is not single-replica and rollback-safe: %#v", name, service.Deploy)
		}
		if service.Deploy.RollbackConfig.Order != "stop-first" {
			t.Fatalf("%s rollback order=%q", name, service.Deploy.RollbackConfig.Order)
		}
	}
	if got := manifest.Services["dockyard"].Deploy.UpdateConfig.Order; got != "start-first" {
		t.Fatalf("dockyard update order=%q", got)
	}
	for _, name := range []string{"postgres", "traefik"} {
		if got := manifest.Services[name].Deploy.UpdateConfig.Order; got != "stop-first" {
			t.Fatalf("%s update order=%q", name, got)
		}
	}
	if !slices.Contains(manifest.Services["traefik"].Command, "--ping=true") {
		t.Fatal("Traefik ping endpoint is not enabled")
	}
	if !slices.Contains(manifest.Services["traefik"].Command, "--providers.file.directory=/etc/traefik/dynamic") || !slices.Contains(manifest.Services["traefik"].Command, "--providers.file.watch=true") {
		t.Fatal("Traefik dynamic file provider is not enabled")
	}
}

func TestProductionManifestsBoundLongRunningResources(t *testing.T) {
	for path, names := range map[string][]string{
		"../../deploy/swarm.yml":       {"postgres", "dockyard", "traefik"},
		"../../deploy/agent-swarm.yml": {"agent"},
		"../../deploy/ai-auditors.yml": {"9router", "headroom", "security-auditor", "reliability-auditor"},
	} {
		manifest := readDeploymentManifest(t, path)
		for _, name := range names {
			resources := manifest.Services[name].Deploy.Resources
			if resources.Limits.CPUs == "" || resources.Limits.Memory == "" || resources.Reservations.CPUs == "" || resources.Reservations.Memory == "" {
				t.Errorf("%s service %s has incomplete resource bounds: %#v", path, name, resources)
			}
		}
	}
}

func TestProductionManifestsBoundLocalLogs(t *testing.T) {
	for path, names := range map[string][]string{
		"../../deploy/swarm.yml":       {"postgres", "dockyard", "traefik"},
		"../../deploy/agent-swarm.yml": {"agent"},
		"../../deploy/ai-auditors.yml": {"9router", "headroom", "security-auditor", "reliability-auditor"},
	} {
		manifest := readDeploymentManifest(t, path)
		for _, name := range names {
			logging := manifest.Services[name].Logging
			if logging.Driver != "local" || logging.Options["max-size"] == "" || logging.Options["max-file"] == "" {
				t.Errorf("%s service %s has unbounded local logs: %#v", path, name, logging)
			}
		}
	}
}

func TestPrivilegedControlProcessesHaveHardenedContainers(t *testing.T) {
	for path, names := range map[string][]string{
		"../../deploy/swarm.yml":       {"dockyard"},
		"../../deploy/agent-swarm.yml": {"agent"},
		"../../deploy/ai-auditors.yml": {"security-auditor", "reliability-auditor"},
	} {
		manifest := readDeploymentManifest(t, path)
		for _, name := range names {
			service := manifest.Services[name]
			if !service.ReadOnly || !slices.Contains(service.CapDrop, "ALL") || !slices.Contains(service.SecurityOpt, "no-new-privileges:true") {
				t.Errorf("%s service %s lacks container hardening: readOnly=%v capDrop=%v securityOpt=%v", path, name, service.ReadOnly, service.CapDrop, service.SecurityOpt)
			}
			if (name == "dockyard" || name == "agent") && !slices.ContainsFunc(service.Tmpfs, func(value string) bool { return strings.HasPrefix(value, "/tmp:") }) {
				t.Errorf("%s service %s has no writable bounded /tmp tmpfs: %v", path, name, service.Tmpfs)
			}
		}
	}
	for path, name := range map[string]string{
		"../../deploy/swarm.yml":       "dockyard",
		"../../deploy/agent-swarm.yml": "agent",
	} {
		service := readDeploymentManifest(t, path).Services[name]
		if !slices.Contains(service.Volumes, "/var/run/docker.sock:/var/run/docker.sock:ro") {
			t.Errorf("%s service %s does not mount the Docker socket read-only: %v", path, name, service.Volumes)
		}
	}
}

func TestAIAuditorTopologySeparatesGatewaySidecarAndAuditorIdentities(t *testing.T) {
	manifest := readDeploymentManifest(t, "../../deploy/ai-auditors.yml")
	for _, name := range []string{"ai-gateway", "ai-auditors"} {
		network, ok := manifest.Networks[name]
		if !ok || network.Driver != "overlay" {
			t.Fatalf("missing private overlay network %s: %#v", name, network)
		}
		if encrypted, ok := network.DriverOpts["encrypted"]; !ok || encrypted != "" {
			t.Fatalf("network %s is not encrypted: %#v", name, network.DriverOpts)
		}
	}
	router := manifest.Services["9router"]
	headroom := manifest.Services["headroom"]
	security := manifest.Services["security-auditor"]
	reliability := manifest.Services["reliability-auditor"]
	if !slices.Contains(router.Networks, "ai-gateway") || !slices.Contains(router.Networks, "ai-auditors") {
		t.Fatalf("9Router must bridge only the gateway and auditor overlays: %v", router.Networks)
	}
	if !slices.Equal(headroom.Networks, []string{"ai-gateway"}) {
		t.Fatalf("Headroom can reach auditor identities: %v", headroom.Networks)
	}
	for name, service := range map[string]struct{ Networks []string }{
		"security-auditor":    {Networks: security.Networks},
		"reliability-auditor": {Networks: reliability.Networks},
	} {
		if !slices.Equal(service.Networks, []string{"ai-auditors"}) {
			t.Errorf("%s can reach the gateway sidecar network: %v", name, service.Networks)
		}
	}
	for name, service := range map[string]struct{ SecurityOpt []string }{
		"9router":  {SecurityOpt: router.SecurityOpt},
		"headroom": {SecurityOpt: headroom.SecurityOpt},
	} {
		if !slices.Contains(service.SecurityOpt, "no-new-privileges:true") {
			t.Errorf("%s can acquire additional process privileges: %v", name, service.SecurityOpt)
		}
	}
}

func TestAIStackUpdatesRollBackWithoutOverlappingIdentitiesOrStateWriters(t *testing.T) {
	manifest := readDeploymentManifest(t, "../../deploy/ai-auditors.yml")
	if probe := manifest.Services["9router"].Healthcheck.Test; !slices.Contains(probe, "http://127.0.0.1:20128/api/health") {
		t.Fatalf("9Router update is not gated by its upstream health endpoint: %v", probe)
	}
	for _, name := range []string{"9router", "headroom", "security-auditor", "reliability-auditor"} {
		service := manifest.Services[name]
		if service.Deploy.UpdateConfig.Order != "stop-first" || service.Deploy.UpdateConfig.FailureAction != "rollback" || service.Deploy.RollbackConfig.Order != "stop-first" {
			t.Errorf("%s has unsafe update/rollback behavior: %#v", name, service.Deploy)
		}
	}
}

func TestControllerManifestExposesPrivateEgressAllowlist(t *testing.T) {
	for path, serviceName := range map[string]string{"../../deploy/swarm.yml": "dockyard", "../../deploy/agent-swarm.yml": "agent"} {
		service := readDeploymentManifest(t, path).Services[serviceName]
		if service.Environment["DOCKYARD_EGRESS_PRIVATE_CIDRS"] != "${DOCKYARD_EGRESS_PRIVATE_CIDRS:-}" {
			t.Errorf("%s private egress allowlist=%q", path, service.Environment["DOCKYARD_EGRESS_PRIVATE_CIDRS"])
		}
	}
}

func TestExternalDatabaseDriverOverlayUsesImmutableImagePath(t *testing.T) {
	service := readDeploymentManifest(t, "../../deploy/swarm-database-drivers.yml").Services["dockyard"]
	if got := service.Environment["DOCKYARD_DATABASE_DRIVER_DIRECTORY"]; got != "/usr/local/lib/dockyard/database-drivers" {
		t.Fatalf("external database driver directory=%q", got)
	}
}

func TestProductionServicesHaveExplicitStopGracePeriods(t *testing.T) {
	for path, minimums := range map[string]map[string]time.Duration{
		"../../deploy/swarm.yml": {
			"postgres": time.Minute,
			"dockyard": 30 * time.Second,
			"traefik":  30 * time.Second,
		},
		"../../deploy/agent-swarm.yml": {
			"agent": 30 * time.Second,
		},
		"../../deploy/ai-auditors.yml": {
			"9router":             30 * time.Second,
			"headroom":            30 * time.Second,
			"security-auditor":    30 * time.Second,
			"reliability-auditor": 30 * time.Second,
		},
	} {
		manifest := readDeploymentManifest(t, path)
		for name, minimum := range minimums {
			configured, err := time.ParseDuration(manifest.Services[name].StopGrace)
			if err != nil || configured < minimum {
				t.Errorf("%s service %s stop_grace_period=%q, want at least %s (parse error=%v)", path, name, manifest.Services[name].StopGrace, minimum, err)
			}
		}
	}
}

func TestAgentManifestRollsBackFailedStartFirstUpdate(t *testing.T) {
	service := readDeploymentManifest(t, "../../deploy/agent-swarm.yml").Services["agent"]
	if service.Deploy.Replicas != 1 || service.Deploy.UpdateConfig.Order != "start-first" || service.Deploy.UpdateConfig.FailureAction != "rollback" || service.Deploy.RollbackConfig.Order != "stop-first" {
		t.Fatalf("unsafe agent rollout policy: %#v", service.Deploy)
	}
}

func TestDevelopmentComposeChecksControllerReadiness(t *testing.T) {
	service := readDeploymentManifest(t, "../../compose.yml").Services["dockyard"]
	if len(service.Healthcheck.Test) == 0 {
		t.Fatal("development controller has no health check")
	}
}

func TestControllerBackupStorageIsProvisionedBySwarm(t *testing.T) {
	manifest := readDeploymentManifest(t, "../../deploy/swarm.yml")
	if _, ok := manifest.Volumes["backup-artifacts"]; !ok {
		t.Fatal("controller backup volume is not declared")
	}
	controller := manifest.Services["dockyard"]
	if !slices.Contains(controller.Volumes, "backup-artifacts:/var/lib/dockyard/backups") {
		t.Fatalf("controller backup directory is not backed by its managed volume: %v", controller.Volumes)
	}
	for _, volume := range controller.Volumes {
		if strings.HasPrefix(volume, "/var/lib/dockyard/backups:") {
			t.Fatalf("controller requires a pre-existing host backup directory: %q", volume)
		}
	}
}

func TestControllerSecretsCanBeVersioned(t *testing.T) {
	manifest := readDeploymentManifest(t, "../../deploy/swarm.yml")
	for logicalName, expectedName := range map[string]string{
		"dockyard_db_password":   "${DOCKYARD_DB_PASSWORD_SECRET:-dockyard_db_password}",
		"dockyard_database_url":  "${DOCKYARD_DATABASE_URL_SECRET:-dockyard_database_url}",
		"dockyard_master_key":    "${DOCKYARD_MASTER_KEY_SECRET:-dockyard_master_key}",
		"dockyard_metrics_token": "${DOCKYARD_METRICS_TOKEN_SECRET:-dockyard_metrics_token}",
	} {
		secret, ok := manifest.Secrets[logicalName]
		if !ok || !secret.External || secret.Name != expectedName {
			t.Errorf("secret %s is not configurable and external: %#v", logicalName, secret)
		}
	}
	for _, logicalName := range []string{"dockyard_database_url", "dockyard_master_key", "dockyard_metrics_token"} {
		if !slices.Contains(manifest.Services["dockyard"].Secrets, any(logicalName)) {
			t.Errorf("controller does not mount logical secret %s", logicalName)
		}
	}
}

func TestAgentEnrollmentSecretCanBeVersioned(t *testing.T) {
	manifest := readDeploymentManifest(t, "../../deploy/agent-swarm.yml")
	secret, ok := manifest.Secrets["dockyard_agent_enrollment_token"]
	if !ok || !secret.External || secret.Name != "${DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET:-dockyard_agent_enrollment_token}" {
		t.Fatalf("agent enrollment secret is not configurable and external: %#v", secret)
	}

	mounts := manifest.Services["agent"].Secrets
	if len(mounts) != 1 {
		t.Fatalf("agent enrollment secret mounts=%#v", mounts)
	}
	mount, ok := mounts[0].(map[string]any)
	if !ok || mount["source"] != "dockyard_agent_enrollment_token" || mount["target"] != "dockyard_agent_enrollment_token" {
		t.Fatalf("agent enrollment secret does not retain a stable container path: %#v", mounts[0])
	}
}

func TestAIAuditorSecretsCanBeVersioned(t *testing.T) {
	manifest := readDeploymentManifest(t, "../../deploy/ai-auditors.yml")
	for logicalName, expectedName := range map[string]string{
		"dockyard_ai_security_auditor_token":    "${DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_SECRET:-dockyard_ai_security_auditor_token}",
		"dockyard_ai_reliability_auditor_token": "${DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_SECRET:-dockyard_ai_reliability_auditor_token}",
		"dockyard_ai_api_key":                   "${DOCKYARD_AI_API_KEY_SECRET:-dockyard_ai_api_key}",
	} {
		secret, ok := manifest.Secrets[logicalName]
		if !ok || !secret.External || secret.Name != expectedName {
			t.Errorf("AI secret %s is not configurable and external: %#v", logicalName, secret)
		}
	}
	if !slices.Contains(manifest.Services["security-auditor"].Secrets, any("dockyard_ai_security_auditor_token")) || slices.Contains(manifest.Services["security-auditor"].Secrets, any("dockyard_ai_reliability_auditor_token")) {
		t.Error("security auditor token mount is not isolated")
	}
	if !slices.Contains(manifest.Services["reliability-auditor"].Secrets, any("dockyard_ai_reliability_auditor_token")) || slices.Contains(manifest.Services["reliability-auditor"].Secrets, any("dockyard_ai_security_auditor_token")) {
		t.Error("reliability auditor token mount is not isolated")
	}
	for _, serviceName := range []string{"security-auditor", "reliability-auditor"} {
		if !slices.Contains(manifest.Services[serviceName].Secrets, any("dockyard_ai_api_key")) {
			t.Errorf("%s does not mount the model gateway key", serviceName)
		}
	}
}

func TestAIGatewayPersistentStateIsPinned(t *testing.T) {
	service := readDeploymentManifest(t, "../../deploy/ai-auditors.yml").Services["9router"]
	if !slices.Contains(service.Volumes, "nine-router-data:/app/data") {
		t.Fatalf("9Router data volume is missing: %v", service.Volumes)
	}
	if !slices.Contains(service.Deploy.Placement.Constraints, "node.id == ${NINEROUTER_STORAGE_NODE_ID:?set the Swarm node ID that owns 9Router data}") {
		t.Fatalf("9Router data is not pinned to its owner node: %v", service.Deploy.Placement.Constraints)
	}
}

func TestHighAvailabilityManifestUsesExternalStateAndAgentTLS(t *testing.T) {
	base := readDeploymentManifest(t, "../../deploy/swarm.yml")
	manifest := readDeploymentManifest(t, "../../deploy/swarm-ha.yml")
	if replicas := manifest.Services["postgres"].Deploy.Replicas; replicas != 0 {
		t.Fatalf("bundled PostgreSQL replicas=%d, want 0", replicas)
	}
	controller := manifest.Services["dockyard"]
	if controller.Deploy.Replicas != 3 {
		t.Fatalf("controller replicas=%d, want 3", controller.Deploy.Replicas)
	}
	if !slices.Contains(base.Services["dockyard"].Deploy.Placement.Constraints, "node.role == manager") || controller.Deploy.Placement.MaxReplicasPerNode != 1 || len(controller.Deploy.Placement.Preferences) != 1 || controller.Deploy.Placement.Preferences[0].Spread != "node.id" {
		t.Fatalf("HA controllers are not distributed one per manager: %#v", controller.Deploy.Placement)
	}
	if controller.Deploy.UpdateConfig.Order != "stop-first" {
		t.Fatalf("HA controller rollout order=%q, want stop-first so three managers can satisfy anti-affinity", controller.Deploy.UpdateConfig.Order)
	}
	if controller.Environment["DOCKYARD_REQUIRE_REMOTE_BACKUPS"] != "true" {
		t.Fatal("HA deployment does not require remote backup storage")
	}
	if controller.Environment["DOCKYARD_REQUIRE_DATABASE_TLS"] != "true" {
		t.Fatal("HA deployment does not require verified PostgreSQL TLS")
	}
	for _, name := range []string{"DOCKYARD_AGENT_CA_CERT_FILE", "DOCKYARD_AGENT_CA_KEY_FILE", "DOCKYARD_AGENT_SERVER_CERT_FILE", "DOCKYARD_AGENT_SERVER_KEY_FILE"} {
		if controller.Environment[name] == "" {
			t.Fatalf("HA deployment does not configure %s", name)
		}
	}
	port, ok := controller.Ports[0].(map[string]any)
	if len(controller.Ports) != 1 || !ok || port["target"] != 8444 || port["published"] != 8444 || port["mode"] != "ingress" {
		t.Fatalf("agent mTLS listener is not published through Swarm ingress: %#v", controller.Ports)
	}
}

func TestControllerIngressUsesIsolatedTrustedProxyNetwork(t *testing.T) {
	manifest := readDeploymentManifest(t, "../../deploy/swarm.yml")
	controller := manifest.Services["dockyard"]
	proxy := manifest.Services["traefik"]
	if !slices.Contains(controller.Networks, "edge-control") || slices.Contains(controller.Networks, "dockyard-public") {
		t.Fatalf("controller networks are not isolated from tenant ingress: %v", controller.Networks)
	}
	if !slices.Contains(proxy.Networks, "edge-control") || !slices.Contains(proxy.Networks, "dockyard-public") {
		t.Fatalf("Traefik does not bridge isolated and public networks: %v", proxy.Networks)
	}
	if controller.Deploy.Labels["traefik.docker.network"] != "${DOCKYARD_EDGE_CONTROL_NETWORK:-dockyard-edge-control}" || controller.Environment["DOCKYARD_TRUSTED_PROXY_CIDRS"] == "" {
		t.Fatalf("controller proxy trust is incomplete: labels=%v environment=%v", controller.Deploy.Labels, controller.Environment)
	}

	auditors, err := os.ReadFile("../../deploy/ai-auditors.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditors), "networks: [dockyard-public") || strings.Contains(string(auditors), "http://dockyard:8080") {
		t.Fatal("AI auditor bypasses isolated public HTTPS ingress")
	}
}

func TestReleaseWorkflowAssignsVersionTagOnlyAfterPromotionGates(t *testing.T) {
	contents, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(contents)
	candidate := strings.Index(workflow, "tags: ${{ steps.release.outputs.image }}:candidate-${{ github.run_id }}-${{ github.run_attempt }}")
	promote := strings.Index(workflow, "- name: Assign verified digest to release tag")
	publish := strings.Index(workflow, "- name: Publish package for anonymous pulls")
	if candidate < 0 || promote < 0 || publish < 0 {
		t.Fatal("release workflow is missing candidate-first promotion steps")
	}
	for _, requiredGate := range []string{
		"- name: Validate vulnerability evidence",
		"- name: Sign and verify immutable digest",
		"- name: Exercise encrypted AI gateway recovery controls",
		"- name: Validate release soak evidence",
		"- name: Aggregate database recovery evidence",
		"- name: Write final release checksums and promotion manifest",
		"- name: Sign and verify promotion manifest",
		"- name: Authenticate production certification and candidate evidence",
	} {
		position := strings.Index(workflow, requiredGate)
		if position < candidate || position > promote {
			t.Errorf("release gate %q does not run between candidate build and version promotion", requiredGate)
		}
	}
	if promote >= publish {
		t.Fatal("release package is made public before the verified digest receives its version tag")
	}
	if strings.Contains(workflow[:promote], "tags: ${{ steps.release.outputs.image }}:${{ steps.release.outputs.version }}") {
		t.Fatal("release workflow assigns the public version tag before promotion gates")
	}
	if !strings.Contains(workflow, "cosign verify-blob") || !strings.Contains(workflow, "evidenceChecksumsSHA256") || !strings.Contains(workflow, "sha256sum --check --strict release-evidence.sha256") {
		t.Fatal("release workflow does not authenticate the promotion manifest and its evidence checksums")
	}
	if !strings.Contains(workflow, "environment: production-release") || !strings.Contains(workflow, "production-certification-$GITHUB_SHA") || !strings.Contains(workflow, "validate-production-certification") {
		t.Fatal("stable release promotion is not gated by exact-candidate production certification")
	}
	certify := strings.Index(workflow, "- name: Authenticate production certification and candidate evidence")
	manifest := strings.Index(workflow, "- name: Write final release checksums and promotion manifest")
	manifestSignature := strings.Index(workflow, "- name: Sign and verify promotion manifest")
	if certify < 0 || manifest <= certify || manifestSignature <= manifest || promote <= manifestSignature {
		t.Fatal("final checksums and promotion manifest must be created and signed after production certification but before stable tagging")
	}
	if !strings.Contains(workflow, "production-certification.json production-certification.sigstore.json") {
		t.Fatal("production certification and its signature bundle are missing from the final checksum inventory")
	}
	for _, recoveryEvidenceContract := range []string{
		"ai-gateway-recovery-conformance.json ai-gateway-recovery-conformance.log",
		`aiGatewayRecoveryConformanceEvidence:"ai-gateway-recovery-conformance.json"`,
		`.candidateEncryptedRoundTripVerified and .candidateRestoredConfigurationVerified`,
		`.helperCleanupRetried and .restoreHelperCleanupRetried`,
		`.permanentCleanupFailureRejected and .permanentSecretCleanupFailureRejected`,
		`.proxyEnvironmentIgnored and .redirectsRejected and .responseHeaderTimeoutEnforced`,
		`.singleSnapshotMetadataVerified`,
		`.candidateManifestVerifierVerified and .candidateTamperedManifestRejected`,
		`.postRestoreDualAuditorVerification == "production-required"`,
	} {
		if !strings.Contains(workflow, recoveryEvidenceContract) {
			t.Errorf("release workflow is missing AI gateway recovery evidence contract %q", recoveryEvidenceContract)
		}
	}
	for _, controlPlaneRecoveryContract := range []string{
		"control-plane-recovery-conformance.json control-plane-recovery-conformance.log",
		`controlPlaneRecoveryEvidence:"control-plane-recovery-conformance.json"`,
		`.signedManifestVerified and .singleSnapshotMetadataVerified and .deploymentIdentityBound`,
		`.agentCAKeypairVerified and .mismatchedAgentCAKeyRejected`,
		`.privateDumpSnapshotVerified and .stagedCutoverVerified and .rollbackDatabaseRetained`,
		`.candidateVerifierImage == $candidateVerifierImage and .candidateManifestVerifierVerified and .candidateTamperedManifestRejected and .candidateAgentCAKeypairVerified`,
		`.auditChainContinuity == "production-required"`,
	} {
		if !strings.Contains(workflow, controlPlaneRecoveryContract) {
			t.Errorf("release workflow is missing control-plane recovery evidence contract %q", controlPlaneRecoveryContract)
		}
	}
	for _, resumableReleaseGuard := range []string{
		`gh release create "$VERSION"`,
		`--draft`,
		`gh release upload "$VERSION" "${assets[@]}"`,
		`--clobber`,
		`gh release download "$VERSION"`,
		`cmp --silent "$asset" "$download_dir/$asset"`,
		`gh release edit "$VERSION" --repo "$GITHUB_REPOSITORY" --draft=false`,
		`existing release $VERSION does not match this promotion`,
	} {
		if !strings.Contains(workflow, resumableReleaseGuard) {
			t.Errorf("release workflow is missing resumable draft guard %q", resumableReleaseGuard)
		}
	}
	for _, releaseChainGuard := range []string{
		"highest stable release",
		"sort --version-sort",
		`git rev-list -n 1 "$PREVIOUS_VERSION"`,
		`.repository == $repository`,
		`startswith($imageRepository + "@sha256:")`,
	} {
		if !strings.Contains(workflow, releaseChainGuard) {
			t.Errorf("release workflow is missing predecessor guard %q", releaseChainGuard)
		}
	}
	if strings.Contains(workflow, "[0-9A-Za-z.-]*)?$") {
		t.Fatal("release workflow accepts prerelease versions as stable releases")
	}
	promotionBlock := workflow[promote:publish]
	if !strings.Contains(promotionBlock, `imagetools inspect --raw "$IMAGE:$VERSION"`) || !strings.Contains(promotionBlock, `existing_digest`) || !strings.Contains(promotionBlock, "instead of verified digest") || !strings.Contains(promotionBlock, "already points to the verified digest; resuming promotion") {
		t.Fatal("release workflow does not safely resume an exact existing version tag or reject a mismatched tag")
	}
	soakContents, err := os.ReadFile("../../scripts/ci/test-release-soak.sh")
	if err != nil {
		t.Fatal(err)
	}
	soak := string(soakContents)
	for _, databaseDriverEvidence := range []string{
		`/v1/database-engines`,
		`["clickhouse","libsql","mariadb","meilisearch","mongo","mysql","postgres","qdrant","redis","timescaledb","valkey"]`,
		`databaseDriverInventoryVerified:true`,
		`databaseDriverCount:11`,
		`.databaseDriverInventoryVerified and .databaseDriverCount == 11`,
	} {
		if !strings.Contains(soak, databaseDriverEvidence) || !strings.Contains(workflow, databaseDriverEvidence) && strings.HasPrefix(databaseDriverEvidence, ".databaseDriver") {
			t.Errorf("release soak is missing database-driver evidence contract %q", databaseDriverEvidence)
		}
	}
}

func TestSSOConformanceEvidenceIsEmittedByTheHarness(t *testing.T) {
	workflowBytes, err := os.ReadFile("../../.github/workflows/sso-conformance.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(workflowBytes)
	if strings.Contains(workflow, "jq -n") {
		t.Fatal("SSO workflow fabricates conformance evidence instead of consuming harness output")
	}
	for _, contract := range []string{
		"DOCKYARD_SSO_EVIDENCE: sso-keycloak-evidence.json",
		`.schemaVersion == 1 and .status == "passed"`,
		`.flows.oidc == {test:"TestKeycloakOIDCConformance",status:"passed"}`,
		`.flows.saml == {test:"TestKeycloakSAMLConformance",status:"passed"}`,
		"scripts/ci/validate-image-reference.sh",
	} {
		if !strings.Contains(workflow, contract) {
			t.Errorf("SSO workflow is missing harness evidence contract %q", contract)
		}
	}

	harnessBytes, err := os.ReadFile("../../scripts/ci/test-keycloak-oidc.sh")
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	oidcPass := strings.Index(harness, "grep -Eq '^--- PASS: TestKeycloakOIDCConformance '")
	samlPass := strings.Index(harness, "grep -Eq '^--- PASS: TestKeycloakSAMLConformance '")
	evidenceWrite := strings.Index(harness, "'{schemaVersion:1,status:\"passed\"")
	evidencePublish := strings.Index(harness, "mv \"$work_dir/sso-keycloak-evidence.json\" \"$evidence_file\"")
	if oidcPass < 0 || samlPass < 0 || evidenceWrite <= oidcPass || evidenceWrite <= samlPass || evidencePublish <= evidenceWrite {
		t.Fatal("SSO harness can publish positive evidence before both named tests pass")
	}
	for _, contract := range []string{
		`rm -f -- "$evidence_file"`,
		`validate-image-reference.sh" "$keycloak_image"`,
		`validate-image-reference.sh" "$postgres_image"`,
		`--arg keycloakImage "$keycloak_image"`,
		`--arg postgresImage "$postgres_image"`,
	} {
		if !strings.Contains(harness, contract) {
			t.Errorf("SSO harness is missing evidence guard %q", contract)
		}
	}
}

func TestControlPlaneRestoreUsesAuthenticatedPrivateSnapshots(t *testing.T) {
	contents, err := os.ReadFile("../../scripts/restore-control-plane.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(contents)
	for _, required := range []string{
		"verify-control-plane-recovery-manifest",
		"--network none --read-only --cap-drop ALL --security-opt no-new-privileges",
		`cp -P -- "$bundle/database.dump" "$temporary/database.dump"`,
		`sha256sum "$temporary/database.dump"`,
		`pg_restore --list <"$temporary/database.dump"`,
		`--exit-on-error <"$temporary/database.dump"`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("control-plane restore is missing snapshot invariant %q", required)
		}
	}
	if strings.Contains(script, `pg_restore --list <"$bundle/database.dump"`) || strings.Contains(script, `--exit-on-error <"$bundle/database.dump"`) {
		t.Fatal("control-plane restore consumes the mutable bundle dump after verification")
	}
}
