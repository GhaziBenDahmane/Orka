package database_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/google/uuid"
)

// TestNativeDatabaseRecoveryConformance is an opt-in staging test. Unlike the
// fast plan tests, it runs the exact backup, restore, and readiness commands
// against real database containers on an attachable Swarm overlay network.
// Run it with DOCKYARD_TEST_DATABASE_RECOVERY=1; narrow a diagnostic run with
// DOCKYARD_TEST_DATABASE_ENGINES=postgres,mongo.
func TestNativeDatabaseRecoveryConformance(t *testing.T) {
	if os.Getenv("DOCKYARD_TEST_DATABASE_RECOVERY") != "1" {
		t.Skip("set DOCKYARD_TEST_DATABASE_RECOVERY=1 to run real database recovery conformance")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	network := "dy-recovery-" + uuid.NewString()[:8]
	docker(t, ctx, nil, "network", "create", "--driver", "overlay", "--attachable", network)
	t.Cleanup(func() { _, _ = dockerOutput(context.Background(), nil, "network", "rm", network) })

	wanted := map[string]bool{}
	for _, name := range strings.Split(os.Getenv("DOCKYARD_TEST_DATABASE_ENGINES"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			wanted[name] = true
		}
	}
	cases := []recoveryCase{
		postgresRecovery(),
		mysqlRecovery("mysql", "8.4"),
		mysqlRecovery("mariadb", "11.8"),
		mongoRecovery(),
		redisRecovery("redis", "8"),
		redisRecovery("valkey", "8"),
		qdrantRecovery(),
	}
	for _, tc := range cases {
		if len(wanted) > 0 && !wanted[tc.engine] {
			continue
		}
		t.Run(tc.engine, func(t *testing.T) { exerciseRecovery(t, ctx, network, tc) })
	}
}

type recoveryCase struct {
	engine       string
	version      string
	image        string
	serverEnv    map[string]string
	serverArgs   []string
	clientImage  string
	clientEnv    map[string]string
	seedCommand  []string
	clearCommand []string
	readCommand  []string
	want         string
}

func qdrantRecovery() recoveryCase {
	return recoveryCase{
		engine: "qdrant", version: "v1.15", image: "qdrant/qdrant",
		serverEnv:    map[string]string{"QDRANT__SERVICE__API_KEY": "recovery-secret"},
		clientImage:  qdrantTestClientImage,
		clientEnv:    map[string]string{"QDRANT_API_KEY": "recovery-secret"},
		seedCommand:  []string{"python3", "-c", qdrantSeedScript},
		clearCommand: []string{"python3", "-c", qdrantClearScript},
		readCommand:  []string{"python3", "-c", qdrantReadScript},
		want:         "dockyard-recovery-ok",
	}
}

func postgresRecovery() recoveryCase {
	return recoveryCase{
		engine: "postgres", version: "17",
		serverEnv:    map[string]string{"POSTGRES_USER": "dockyard", "POSTGRES_PASSWORD": "recovery-secret", "POSTGRES_DB": "app"},
		seedCommand:  []string{"psql", "--username", "dockyard", "--dbname", "app", "--command", "CREATE TABLE recovery_probe(value text); INSERT INTO recovery_probe VALUES ('dockyard-recovery-ok');"},
		clearCommand: []string{"psql", "--username", "dockyard", "--dbname", "app", "--command", "DROP TABLE recovery_probe;"},
		readCommand:  []string{"psql", "--username", "dockyard", "--dbname", "app", "--tuples-only", "--no-align", "--command", "SELECT value FROM recovery_probe;"},
		want:         "dockyard-recovery-ok",
	}
}

func mysqlRecovery(engine, version string) recoveryCase {
	prefix, client := "MYSQL", "mysql"
	if engine == "mariadb" {
		prefix, client = "MARIADB", "mariadb"
	}
	return recoveryCase{
		engine: engine, version: version,
		serverEnv:    map[string]string{prefix + "_USER": "dockyard", prefix + "_PASSWORD": "recovery-secret", prefix + "_DATABASE": "app", prefix + "_ROOT_PASSWORD": "root-recovery-secret"},
		seedCommand:  []string{client, "--user", "dockyard", "--database", "app", "--execute", "CREATE TABLE recovery_probe(value varchar(64)); INSERT INTO recovery_probe VALUES ('dockyard-recovery-ok');"},
		clearCommand: []string{client, "--user", "dockyard", "--database", "app", "--execute", "DROP TABLE recovery_probe;"},
		readCommand:  []string{client, "--user", "dockyard", "--database", "app", "--batch", "--skip-column-names", "--execute", "SELECT value FROM recovery_probe;"},
		want:         "dockyard-recovery-ok",
	}
}

func mongoRecovery() recoveryCase {
	auth := []string{"mongosh", "--quiet", "--username", "dockyard", "--password", "recovery-secret", "--authenticationDatabase", "admin", "app", "--eval"}
	return recoveryCase{
		engine: "mongo", version: "8",
		serverEnv:    map[string]string{"MONGO_INITDB_ROOT_USERNAME": "dockyard", "MONGO_INITDB_ROOT_PASSWORD": "recovery-secret", "MONGO_INITDB_DATABASE": "app"},
		seedCommand:  append(append([]string{}, auth...), `db.recovery_probe.insertOne({_id:"probe",value:"dockyard-recovery-ok"})`),
		clearCommand: append(append([]string{}, auth...), `db.recovery_probe.drop()`),
		readCommand:  append(append([]string{}, auth...), `db.recovery_probe.findOne({_id:"probe"}).value`),
		want:         "dockyard-recovery-ok",
	}
}

func redisRecovery(engine, version string) recoveryCase {
	cli, server, image := "redis-cli", "redis-server", "redis"
	if engine == "valkey" {
		cli, server, image = "valkey-cli", "valkey-server", "valkey/valkey"
	}
	return recoveryCase{
		engine: engine, version: version, image: image,
		serverArgs:   []string{server, "--appendonly", "yes", "--requirepass", "recovery-secret"},
		seedCommand:  []string{cli, "EVAL", `redis.call('SET','recovery_probe','dockyard-recovery-ok'); redis.call('HSET','recovery_hash','field','hash-ok'); redis.call('PEXPIRE','recovery_probe',600000); return 'OK'`, "0"},
		clearCommand: []string{cli, "FLUSHALL"},
		readCommand:  []string{cli, "--raw", "EVAL", `local ttl=redis.call('PTTL','recovery_probe'); return redis.call('GET','recovery_probe')..'|'..redis.call('HGET','recovery_hash','field')..'|'..(ttl>0 and 'ttl' or 'no-ttl')`, "0"},
		want:         "dockyard-recovery-ok|hash-ok|ttl",
	}
}

func exerciseRecovery(t *testing.T, ctx context.Context, network string, tc recoveryCase) {
	t.Helper()
	registry := database.NewRegistry()
	credentials := map[string]string{"username": "dockyard", "password": "recovery-secret", "database": "app"}
	container := "dy-" + tc.engine + "-" + uuid.NewString()[:8]
	args := []string{"run", "--detach", "--name", container, "--network", network}
	for key, value := range tc.serverEnv {
		args = append(args, "--env", key+"="+value)
	}
	image := tc.image
	if image == "" {
		image = tc.engine
	}
	args = append(args, image+":"+tc.version)
	args = append(args, tc.serverArgs...)
	docker(t, ctx, nil, args...)
	t.Cleanup(func() { _, _ = dockerOutput(context.Background(), nil, "rm", "--force", container) })

	scheduler := deploy.Swarm{DockerBin: "docker"}
	readiness, err := registry.Readiness(tc.engine, tc.version, container, credentials)
	if err != nil {
		t.Fatal(err)
	}
	waitForRecoveryDatabase(t, ctx, scheduler, network, readiness, container)

	clientEnv := map[string]string{"PGPASSWORD": credentials["password"], "MYSQL_PWD": credentials["password"], "REDISCLI_AUTH": credentials["password"]}
	for key, value := range tc.clientEnv {
		clientEnv[key] = value
	}
	clientEnv["QDRANT_HOST"] = container
	runRecoveryClient(t, ctx, scheduler, network, container, tc, clientEnv, tc.seedCommand)
	seededAt := time.Now()
	directory := t.TempDir()
	extension, ok := registry.BackupExtension(tc.engine)
	if !ok {
		t.Fatalf("%s is not advertised as backup-capable", tc.engine)
	}
	filename := uuid.NewString() + "." + extension
	backup, err := registry.Backup(tc.engine, tc.version, container, credentials, filename)
	if err != nil {
		t.Fatal(err)
	}
	writePlanFiles(t, directory, backup.Files)
	backupStarted := time.Now()
	if _, err = scheduler.RunContainerJob(ctx, network, backup.Image, directory, backup.Environment, backup.Command); err != nil {
		t.Fatal(err)
	}
	backupFinished := time.Now()
	info, err := os.Stat(filepath.Join(directory, filename))
	if err != nil || info.Size() == 0 {
		t.Fatalf("backup artifact missing or empty: size=%d err=%v", sizeOf(info), err)
	}
	runRecoveryClient(t, ctx, scheduler, network, container, tc, clientEnv, tc.clearCommand)

	restore, err := registry.Restore(tc.engine, tc.version, container, credentials, filename)
	if err != nil {
		t.Fatal(err)
	}
	writePlanFiles(t, directory, restore.Files)
	restoreStarted := time.Now()
	if _, err = scheduler.RunContainerJob(ctx, network, restore.Image, directory, restore.Environment, restore.Command); err != nil {
		t.Fatal(err)
	}
	restoreFinished := time.Now()
	verifyRecoveryData(t, ctx, scheduler, network, clientEnv, container, tc)
	docker(t, ctx, nil, "restart", container)
	waitForRecoveryDatabase(t, ctx, scheduler, network, readiness, container)
	verifyRecoveryData(t, ctx, scheduler, network, clientEnv, container, tc)
	evidence, _ := json.Marshal(map[string]any{"engine": tc.engine, "version": tc.version, "rpoSeconds": backupFinished.Sub(seededAt).Seconds(), "backupSeconds": backupFinished.Sub(backupStarted).Seconds(), "rtoSeconds": restoreFinished.Sub(restoreStarted).Seconds(), "artifactBytes": info.Size(), "dataVerified": true, "restartVerified": true})
	t.Logf("RECOVERY_EVIDENCE %s", evidence)
}

func waitForRecoveryDatabase(t *testing.T, ctx context.Context, scheduler deploy.Swarm, network string, readiness database.BackupPlan, container string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		attempt, attemptCancel := context.WithTimeout(ctx, 15*time.Second)
		_, err := scheduler.RunContainerJob(attempt, network, readiness.Image, "", readiness.Environment, readiness.Command)
		attemptCancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("database did not become ready: %v\n%s", err, dockerLogs(container))
		}
		time.Sleep(2 * time.Second)
	}
}

func verifyRecoveryData(t *testing.T, ctx context.Context, scheduler deploy.Swarm, network string, clientEnv map[string]string, container string, tc recoveryCase) {
	t.Helper()
	output := strings.TrimSpace(runRecoveryClient(t, ctx, scheduler, network, container, tc, clientEnv, tc.readCommand))
	if !strings.Contains(output, tc.want) {
		t.Fatalf("restored application data=%q, want %q", output, tc.want)
	}
}

func runRecoveryClient(t *testing.T, ctx context.Context, scheduler deploy.Swarm, network, container string, tc recoveryCase, environment map[string]string, command []string) string {
	t.Helper()
	if tc.clientImage != "" {
		output, err := scheduler.RunContainerJob(ctx, network, tc.clientImage, "", environment, command)
		if err != nil {
			t.Fatalf("database client job: %v\n%s", err, output)
		}
		return output
	}
	return docker(t, ctx, environment, append([]string{"exec"}, append(envArgs(environment), append([]string{container}, command...)...)...)...)
}

const qdrantTestClientImage = "python:3.13-alpine"

const qdrantSeedScript = `
import json, os, urllib.request
base = "http://%s:6333" % os.environ["QDRANT_HOST"]
headers = {"api-key": os.environ["QDRANT_API_KEY"], "content-type": "application/json"}
def put(path, value):
    data = json.dumps(value).encode()
    with urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers=headers, method="PUT"), timeout=30) as response:
        if response.status < 200 or response.status >= 300: raise RuntimeError(response.status)
put("/collections/recovery_probe", {"vectors": {"size": 4, "distance": "Cosine"}})
put("/collections/recovery_probe/points?wait=true", {"points": [{"id": 1, "vector": [1, 0, 0, 0], "payload": {"value": "dockyard-recovery-ok"}}]})
`

const qdrantClearScript = `
import os, urllib.request
url = "http://%s:6333/collections/recovery_probe" % os.environ["QDRANT_HOST"]
with urllib.request.urlopen(urllib.request.Request(url, headers={"api-key": os.environ["QDRANT_API_KEY"]}, method="DELETE"), timeout=30) as response:
    if response.status < 200 or response.status >= 300: raise RuntimeError(response.status)
`

const qdrantReadScript = `
import json, os, urllib.request
url = "http://%s:6333/collections/recovery_probe/points/1" % os.environ["QDRANT_HOST"]
with urllib.request.urlopen(urllib.request.Request(url, headers={"api-key": os.environ["QDRANT_API_KEY"]}), timeout=30) as response:
    print(json.load(response)["result"]["payload"]["value"])
`

func envArgs(values map[string]string) []string {
	args := make([]string, 0, len(values)*2)
	for key := range values {
		args = append(args, "--env", key)
	}
	return args
}

func writePlanFiles(t *testing.T, directory string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func docker(t *testing.T, ctx context.Context, environment map[string]string, args ...string) string {
	t.Helper()
	output, err := dockerOutput(ctx, environment, args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func dockerOutput(ctx context.Context, environment map[string]string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	command.Env = os.Environ()
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func dockerLogs(container string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, _ := dockerOutput(ctx, nil, "logs", container)
	return output
}

func sizeOf(info os.FileInfo) int64 {
	if info == nil {
		return 0
	}
	return info.Size()
}
