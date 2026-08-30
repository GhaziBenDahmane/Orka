package database

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Request struct {
	Name, Version string
	Config        map[string]any
}
type Result struct {
	ComposeYAML string
	Environment map[string]string
	Credentials map[string]string
	InternalURL string
	Version     string
}
type Driver interface {
	Name() string
	DefaultVersion() string
	Render(Request) (Result, error)
}
type BackupPlan struct {
	Image       string
	Command     []string
	Environment map[string]string
	Extension   string
	Files       map[string]string
}
type SourceConnection struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
	Port     int    `json:"port,omitempty"`
}
type RestorePlan = BackupPlan
type Registry struct{ drivers map[string]Driver }

type EngineInfo struct {
	Name            string `json:"name"`
	DefaultVersion  string `json:"defaultVersion"`
	Source          string `json:"source"`
	BackupCapable   bool   `json:"backupCapable"`
	BackupExtension string `json:"backupExtension"`
}

var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func NewRegistry() *Registry {
	r := &Registry{drivers: map[string]Driver{}}
	for _, d := range []Driver{
		simpleDriver{name: "postgres", version: "17", image: "postgres", port: 5432, userKey: "POSTGRES_USER", passwordKey: "POSTGRES_PASSWORD", databaseKey: "POSTGRES_DB", dataPath: "/var/lib/postgresql/data", scheme: "postgres"},
		simpleDriver{name: "mysql", version: "8.4", image: "mysql", port: 3306, userKey: "MYSQL_USER", passwordKey: "MYSQL_PASSWORD", databaseKey: "MYSQL_DATABASE", rootPasswordKey: "MYSQL_ROOT_PASSWORD", dataPath: "/var/lib/mysql", scheme: "mysql"},
		simpleDriver{name: "mariadb", version: "11.8", image: "mariadb", port: 3306, userKey: "MARIADB_USER", passwordKey: "MARIADB_PASSWORD", databaseKey: "MARIADB_DATABASE", rootPasswordKey: "MARIADB_ROOT_PASSWORD", dataPath: "/var/lib/mysql", scheme: "mysql"},
		simpleDriver{name: "mongo", version: "8", image: "mongo", port: 27017, userKey: "MONGO_INITDB_ROOT_USERNAME", passwordKey: "MONGO_INITDB_ROOT_PASSWORD", databaseKey: "MONGO_INITDB_DATABASE", dataPath: "/data/db", scheme: "mongodb"},
		simpleDriver{name: "valkey", version: "8", image: "valkey/valkey", port: 6379, dataPath: "/data", scheme: "redis", commandPassword: true, commandBinary: "valkey-server", passwordOnlyURL: true},
		simpleDriver{name: "redis", version: "8", image: "redis", port: 6379, dataPath: "/data", scheme: "redis", commandPassword: true, commandBinary: "redis-server", passwordOnlyURL: true},
		simpleDriver{name: "libsql", version: "v0.24.33", image: "ghcr.io/tursodatabase/libsql-server", port: 8080, dataPath: "/var/lib/sqld", scheme: "http", basicAuthURL: true, httpBasicAuth: true},
		simpleDriver{name: "clickhouse", version: "25.8-alpine", image: "clickhouse/clickhouse-server", port: 8123, userKey: "CLICKHOUSE_USER", passwordKey: "CLICKHOUSE_PASSWORD", databaseKey: "CLICKHOUSE_DB", dataPath: "/var/lib/clickhouse", scheme: "http", basicAuthURL: true},
		simpleDriver{name: "qdrant", version: "v1.15", image: "qdrant/qdrant", port: 6333, passwordKey: "QDRANT__SERVICE__API_KEY", dataPath: "/qdrant/storage", scheme: "http"},
		simpleDriver{name: "meilisearch", version: "v1.20", image: "getmeili/meilisearch", port: 7700, passwordKey: "MEILI_MASTER_KEY", dataPath: "/meili_data", scheme: "http"},
	} {
		r.drivers[d.Name()] = d
	}
	return r
}
func (r *Registry) Names() []string {
	engines := r.Engines()
	names := make([]string, 0, len(engines))
	for _, engine := range engines {
		names = append(names, engine.Name)
	}
	return names
}

// Engines returns stable, public metadata for every registered database
// driver. It deliberately reports only the driver's trust source and never
// exposes the executable path used by an external driver.
func (r *Registry) Engines() []EngineInfo {
	engines := make([]EngineInfo, 0, len(r.drivers))
	for name, driver := range r.drivers {
		extension, backupCapable := r.BackupExtension(name)
		source := "built-in"
		if _, external := driver.(*externalDriver); external {
			source = "external"
		}
		engines = append(engines, EngineInfo{
			Name:            name,
			DefaultVersion:  driver.DefaultVersion(),
			Source:          source,
			BackupCapable:   backupCapable,
			BackupExtension: extension,
		})
	}
	sort.Slice(engines, func(i, j int) bool { return engines[i].Name < engines[j].Name })
	return engines
}
func (r *Registry) Render(engine string, request Request) (Result, error) {
	driver, ok := r.drivers[engine]
	if !ok {
		return Result{}, fmt.Errorf("unsupported database engine %q", engine)
	}
	if request.Version == "" {
		request.Version = driver.DefaultVersion()
	}
	if !safeVersion.MatchString(request.Version) {
		return Result{}, fmt.Errorf("invalid database image version")
	}
	return driver.Render(request)
}

func (r *Registry) Backup(engine, version, host string, credentials map[string]string, filename string) (BackupPlan, error) {
	if driver, ok := r.drivers[engine].(*externalDriver); ok {
		return driver.Backup(version, host, credentials, filename)
	}
	if err := validateNativePlan(engine, version, host, credentials, filename); err != nil {
		return BackupPlan{}, err
	}
	switch engine {
	case "postgres":
		command := []string{"pg_dump", "--host", host, "--username", credentials["username"], "--dbname", credentials["database"], "--format=custom", "--file", "/backup/" + filename}
		command = append(command, nativePortArguments(engine, credentials)...)
		return BackupPlan{Image: "postgres:" + version, Command: command, Environment: map[string]string{"PGPASSWORD": credentials["password"]}, Extension: "dump"}, nil
	case "mysql":
		command := []string{"mysqldump", "--host", host, "--user", credentials["username"], "--single-transaction", "--routines", "--events", "--no-tablespaces", "--result-file=/backup/" + filename}
		command = append(command, nativePortArguments(engine, credentials)...)
		command = append(command, credentials["database"])
		return BackupPlan{Image: "mysql:" + version, Command: command, Environment: map[string]string{"MYSQL_PWD": credentials["password"]}, Extension: "sql"}, nil
	case "mariadb":
		command := []string{"mariadb-dump", "--host", host, "--user", credentials["username"], "--single-transaction", "--routines", "--events", "--result-file=/backup/" + filename}
		command = append(command, nativePortArguments(engine, credentials)...)
		command = append(command, credentials["database"])
		return BackupPlan{Image: "mariadb:" + version, Command: command, Environment: map[string]string{"MYSQL_PWD": credentials["password"]}, Extension: "sql"}, nil
	case "mongo":
		configName := filename + ".config"
		command := []string{"mongodump", "--config=/backup/" + configName, "--host", host, "--username", credentials["username"], "--authenticationDatabase", "admin", "--db", credentials["database"], "--archive=/backup/" + filename, "--gzip"}
		command = append(command, nativePortArguments(engine, credentials)...)
		return BackupPlan{Image: "mongo:" + version, Command: command, Extension: "archive.gz", Files: map[string]string{configName: "password: " + mongoYAMLString(credentials["password"]) + "\n"}}, nil
	case "redis", "valkey":
		cli, _, image := redisTools(engine, version)
		return BackupPlan{
			Image: image, Command: []string{cli, "-h", host, "-p", nativePort(credentials, 6379), "--rdb", "/backup/" + filename},
			Environment: map[string]string{"REDISCLI_AUTH": credentials["password"]}, Extension: "rdb",
		}, nil
	case "qdrant":
		return qdrantBackupPlan(host, credentials, filename), nil
	case "meilisearch":
		return meilisearchBackupPlan(host, credentials, filename), nil
	case "libsql":
		return libSQLBackupPlan(host, credentials, filename), nil
	case "clickhouse":
		return clickHouseBackupPlan(version, host, credentials, filename), nil
	default:
		return BackupPlan{}, fmt.Errorf("verified backups are not implemented for database engine %q", engine)
	}
}

func (r *Registry) Restore(engine, version, host string, credentials map[string]string, filename string) (RestorePlan, error) {
	if driver, ok := r.drivers[engine].(*externalDriver); ok {
		return driver.Restore(version, host, credentials, filename)
	}
	if err := validateNativePlan(engine, version, host, credentials, filename); err != nil {
		return RestorePlan{}, err
	}
	switch engine {
	case "postgres":
		return RestorePlan{Image: "postgres:" + version, Command: []string{"pg_restore", "--clean", "--if-exists", "--no-owner", "--host", host, "--username", credentials["username"], "--dbname", credentials["database"], "/backup/" + filename}, Environment: map[string]string{"PGPASSWORD": credentials["password"]}, Extension: "dump"}, nil
	case "mysql":
		return RestorePlan{Image: "mysql:" + version, Command: []string{"mysql", "--host", host, "--user", credentials["username"], "--database", credentials["database"], "--execute", "source /backup/" + filename}, Environment: map[string]string{"MYSQL_PWD": credentials["password"]}, Extension: "sql"}, nil
	case "mariadb":
		return RestorePlan{Image: "mariadb:" + version, Command: []string{"mariadb", "--host", host, "--user", credentials["username"], "--database", credentials["database"], "--execute", "source /backup/" + filename}, Environment: map[string]string{"MYSQL_PWD": credentials["password"]}, Extension: "sql"}, nil
	case "mongo":
		configName := filename + ".config"
		return RestorePlan{Image: "mongo:" + version, Command: []string{"mongorestore", "--config=/backup/" + configName, "--host", host, "--username", credentials["username"], "--authenticationDatabase", "admin", "--db", credentials["database"], "--archive=/backup/" + filename, "--gzip", "--drop"}, Extension: "archive.gz", Files: map[string]string{configName: "password: " + mongoYAMLString(credentials["password"]) + "\n"}}, nil
	case "redis", "valkey":
		cli, server, image := redisTools(engine, version)
		return RestorePlan{
			Image:   image,
			Command: []string{"sh", "-eu", "-c", redisRestoreScript},
			Environment: map[string]string{
				"REDISCLI_AUTH": credentials["password"], "DOCKYARD_REDIS_HOST": host, "DOCKYARD_REDIS_PORT": nativePort(credentials, 6379),
				"DOCKYARD_REDIS_RDB": filename, "DOCKYARD_REDIS_CLI": cli, "DOCKYARD_REDIS_SERVER": server, "DOCKYARD_REDIS_SOURCE_PASSWORD": secret(32),
			},
			Extension: "rdb",
		}, nil
	case "qdrant":
		return qdrantRestorePlan(host, credentials, filename), nil
	case "meilisearch":
		return meilisearchRestorePlan(host, credentials, filename), nil
	case "libsql":
		return libSQLRestorePlan(host, credentials, filename), nil
	case "clickhouse":
		return clickHouseRestorePlan(version, host, credentials, filename), nil
	default:
		return RestorePlan{}, fmt.Errorf("verified restore is not implemented for database engine %q", engine)
	}
}

func (r *Registry) BackupExtension(engine string) (string, bool) {
	if driver, ok := r.drivers[engine].(*externalDriver); ok {
		return driver.BackupExtension()
	}
	switch engine {
	case "postgres":
		return "dump", true
	case "mysql", "mariadb":
		return "sql", true
	case "libsql":
		return "sql", true
	case "clickhouse":
		return "tar.gz", true
	case "mongo":
		return "archive.gz", true
	case "redis", "valkey":
		return "rdb", true
	case "qdrant", "meilisearch":
		return "tar.gz", true
	default:
		return "", false
	}
}

func (r *Registry) Readiness(engine, version, host string, credentials map[string]string) (BackupPlan, error) {
	if driver, ok := r.drivers[engine].(*externalDriver); ok {
		return driver.Readiness(version, host, credentials)
	}
	if !safeVersion.MatchString(version) || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`).MatchString(host) {
		return BackupPlan{}, errors.New("invalid database readiness parameters")
	}
	switch engine {
	case "postgres":
		return BackupPlan{Image: "postgres:" + version, Command: []string{"pg_isready", "--host", host, "--username", credentials["username"], "--dbname", credentials["database"]}, Environment: map[string]string{"PGPASSWORD": credentials["password"]}}, nil
	case "mysql":
		return BackupPlan{Image: "mysql:" + version, Command: []string{"mysqladmin", "--host", host, "--user", credentials["username"], "ping", "--silent"}, Environment: map[string]string{"MYSQL_PWD": credentials["password"]}}, nil
	case "mariadb":
		return BackupPlan{Image: "mariadb:" + version, Command: []string{"mariadb-admin", "--host", host, "--user", credentials["username"], "ping", "--silent"}, Environment: map[string]string{"MYSQL_PWD": credentials["password"]}}, nil
	case "mongo":
		// mongosh does not consume MONGODB_PWD. Build the URI inside the shell
		// process so the password remains in the container environment instead
		// of appearing in Docker's command metadata or the host process list.
		probe := `const uri="mongodb://"+encodeURIComponent(process.env.DOCKYARD_MONGO_USER)+":"+encodeURIComponent(process.env.DOCKYARD_MONGO_PASSWORD)+"@"+process.env.DOCKYARD_MONGO_HOST+"/"+encodeURIComponent(process.env.DOCKYARD_MONGO_DATABASE)+"?authSource=admin"; const client=new Mongo(uri); const ok=client.getDB(process.env.DOCKYARD_MONGO_DATABASE).runCommand({ping:1}).ok; quit(ok ? 0 : 1)`
		return BackupPlan{Image: "mongo:" + version, Command: []string{"mongosh", "--quiet", "--nodb", "--eval", probe}, Environment: map[string]string{"DOCKYARD_MONGO_HOST": host, "DOCKYARD_MONGO_USER": credentials["username"], "DOCKYARD_MONGO_PASSWORD": credentials["password"], "DOCKYARD_MONGO_DATABASE": credentials["database"]}}, nil
	case "redis", "valkey":
		cli, _, image := redisTools(engine, version)
		return BackupPlan{Image: image, Command: []string{cli, "-h", host, "-p", nativePort(credentials, 6379), "ping"}, Environment: map[string]string{"REDISCLI_AUTH": credentials["password"]}}, nil
	case "qdrant":
		return qdrantReadinessPlan(host, credentials), nil
	case "meilisearch":
		return meilisearchReadinessPlan(host, credentials), nil
	case "libsql":
		return libSQLReadinessPlan(host, credentials), nil
	case "clickhouse":
		return clickHouseReadinessPlan(version, host, credentials), nil
	default:
		return BackupPlan{}, fmt.Errorf("readiness probe is not implemented for database engine %q", engine)
	}
}

func validateNativePlan(engine, version, host string, credentials map[string]string, filename string) error {
	if !safeVersion.MatchString(version) || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`).MatchString(host) || !regexp.MustCompile(`^[a-f0-9-]+\.(dump|sql|archive\.gz|rdb|tar\.gz)$`).MatchString(filename) {
		return errors.New("invalid native backup parameters")
	}
	required := []string{"username", "password", "database"}
	if engine == "redis" || engine == "valkey" || engine == "qdrant" || engine == "meilisearch" {
		required = []string{"password"}
	}
	for _, key := range required {
		if credentials[key] == "" {
			return fmt.Errorf("database credential %q is missing", key)
		}
	}
	if value := credentials["port"]; value != "" {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return errors.New("database port must be between 1 and 65535")
		}
	}
	return nil
}

func nativePortArguments(engine string, credentials map[string]string) []string {
	if credentials["port"] == "" {
		return nil
	}
	if engine == "postgres" || engine == "mongo" {
		return []string{"--port", credentials["port"]}
	}
	return []string{"--port=" + credentials["port"]}
}

func nativePort(credentials map[string]string, fallback int) string {
	if credentials["port"] != "" {
		return credentials["port"]
	}
	return strconv.Itoa(fallback)
}

func redisTools(engine, version string) (cli, server, image string) {
	if engine == "valkey" {
		return "valkey-cli", "valkey-server", "valkey/valkey:" + version
	}
	return "redis-cli", "redis-server", "redis:" + version
}

const redisRestoreScript = `
config=/tmp/dockyard-redis-restore.conf
cleanup() {
  "$DOCKYARD_REDIS_CLI" -h "$DOCKYARD_REDIS_HOST" -p "$DOCKYARD_REDIS_PORT" REPLICAOF NO ONE >/dev/null 2>&1 || true
  "$DOCKYARD_REDIS_CLI" -h "$DOCKYARD_REDIS_HOST" -p "$DOCKYARD_REDIS_PORT" CONFIG SET masterauth "" >/dev/null 2>&1 || true
  REDISCLI_AUTH="$DOCKYARD_REDIS_SOURCE_PASSWORD" "$DOCKYARD_REDIS_CLI" -h 127.0.0.1 -p 6380 shutdown nosave >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
umask 077
printf 'bind 0.0.0.0\nprotected-mode yes\nport 6380\ndir /backup\ndbfilename %s\nappendonly no\nsave ""\nrequirepass %s\n' "$DOCKYARD_REDIS_RDB" "$DOCKYARD_REDIS_SOURCE_PASSWORD" >"$config"
"$DOCKYARD_REDIS_SERVER" "$config" --daemonize yes
ready=false
for attempt in $(seq 1 30); do
  if REDISCLI_AUTH="$DOCKYARD_REDIS_SOURCE_PASSWORD" "$DOCKYARD_REDIS_CLI" -h 127.0.0.1 -p 6380 ping >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
source_ip="$(hostname -i | awk '{print $1}')"
printf '%s' "$DOCKYARD_REDIS_SOURCE_PASSWORD" | "$DOCKYARD_REDIS_CLI" -h "$DOCKYARD_REDIS_HOST" -p "$DOCKYARD_REDIS_PORT" -x CONFIG SET masterauth >/dev/null
"$DOCKYARD_REDIS_CLI" -h "$DOCKYARD_REDIS_HOST" -p "$DOCKYARD_REDIS_PORT" REPLICAOF "$source_ip" 6380 >/dev/null
synced=false
for attempt in $(seq 1 120); do
  replication="$("$DOCKYARD_REDIS_CLI" -h "$DOCKYARD_REDIS_HOST" -p "$DOCKYARD_REDIS_PORT" INFO replication 2>/dev/null || true)"
  case "$replication" in *master_link_status:up*master_sync_in_progress:0*) synced=true; break;; esac
  sleep 1
done
test "$synced" = true
"$DOCKYARD_REDIS_CLI" -h "$DOCKYARD_REDIS_HOST" -p "$DOCKYARD_REDIS_PORT" REPLICAOF NO ONE >/dev/null
"$DOCKYARD_REDIS_CLI" -h "$DOCKYARD_REDIS_HOST" -p "$DOCKYARD_REDIS_PORT" CONFIG SET masterauth "" >/dev/null
trap - EXIT INT TERM
REDISCLI_AUTH="$DOCKYARD_REDIS_SOURCE_PASSWORD" "$DOCKYARD_REDIS_CLI" -h 127.0.0.1 -p 6380 shutdown nosave >/dev/null
`

func mongoYAMLString(value string) string {
	data, _ := yaml.Marshal(value)
	return strings.TrimSpace(string(data))
}

type simpleDriver struct {
	name, version, image                                                 string
	port                                                                 int
	userKey, passwordKey, databaseKey, rootPasswordKey, dataPath, scheme string
	commandPassword                                                      bool
	commandBinary                                                        string
	passwordOnlyURL, basicAuthURL                                        bool
	httpBasicAuth                                                        bool
}

func (d simpleDriver) Name() string           { return d.name }
func (d simpleDriver) DefaultVersion() string { return d.version }
func (d simpleDriver) Render(req Request) (Result, error) {
	if req.Name == "" {
		return Result{}, fmt.Errorf("database name is required")
	}
	user := configString(req.Config, "username", "dockyard")
	databaseName := configString(req.Config, "database", "app")
	password := configString(req.Config, "password", secret(32))
	rootPassword := configString(req.Config, "rootPassword", secret(32))
	if d.httpBasicAuth && strings.Contains(user, ":") {
		return Result{}, fmt.Errorf("database username cannot contain a colon")
	}
	image := configString(req.Config, "image", d.image+":"+req.Version)
	if !registryImagePattern.MatchString(image) || strings.Contains(image, "..") {
		return Result{}, fmt.Errorf("invalid database image")
	}
	env := map[string]string{}
	credentials := map[string]string{"username": user, "password": password, "database": databaseName}
	if d.userKey != "" {
		env[d.userKey] = user
	}
	if d.passwordKey != "" {
		env[d.passwordKey] = password
	}
	if d.databaseKey != "" {
		env[d.databaseKey] = databaseName
	}
	if d.rootPasswordKey != "" {
		env[d.rootPasswordKey] = rootPassword
		credentials["rootPassword"] = rootPassword
	}
	if d.commandPassword {
		env["DATABASE_PASSWORD"] = password
	}
	if d.httpBasicAuth {
		env["SQLD_HTTP_AUTH"] = "basic:" + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	}
	service := map[string]any{"image": image, "volumes": []any{req.Name + "-data:" + d.dataPath}, "networks": []any{"default"}, "deploy": map[string]any{"restart_policy": map[string]any{"condition": "on-failure"}}}
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		refs := make([]any, 0, len(keys))
		for _, k := range keys {
			refs = append(refs, k+"=${"+k+"}")
		}
		service["environment"] = refs
	}
	if d.commandPassword {
		service["command"] = []any{d.commandBinary, "--appendonly", "yes", "--requirepass", "${DATABASE_PASSWORD}"}
	}
	doc := map[string]any{"services": map[string]any{req.Name: service}, "volumes": map[string]any{req.Name + "-data": map[string]any{}}, "networks": map[string]any{"default": map[string]any{"attachable": true}}}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return Result{}, err
	}
	connection := &url.URL{Scheme: d.scheme, Host: net.JoinHostPort(req.Name, strconv.Itoa(d.port))}
	if d.passwordOnlyURL {
		connection.User = url.UserPassword("", password)
		connection.Path = "/0"
	} else if d.scheme != "http" || d.basicAuthURL {
		connection.User = url.UserPassword(user, password)
		connection.Path = "/" + databaseName
	}
	return Result{ComposeYAML: string(out), Environment: env, Credentials: credentials, InternalURL: connection.String(), Version: req.Version}, nil
}

var registryImagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}$`)

func configString(config map[string]any, key, fallback string) string {
	if value, ok := config[key].(string); ok && value != "" {
		return value
	}
	return fallback
}

// StoredConfig removes values that belong only in encrypted credentials and
// environment storage before persisting driver configuration.
func StoredConfig(config map[string]any) map[string]any {
	stored := make(map[string]any, len(config))
	for key, value := range config {
		if key != "password" && key != "rootPassword" {
			stored[key] = value
		}
	}
	return stored
}

func secret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")[:n]
}
