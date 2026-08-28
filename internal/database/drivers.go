package database

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
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
type RestorePlan = BackupPlan
type Registry struct{ drivers map[string]Driver }

var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func NewRegistry() *Registry {
	r := &Registry{drivers: map[string]Driver{}}
	for _, d := range []Driver{
		simpleDriver{name: "postgres", version: "17", image: "postgres", port: 5432, userKey: "POSTGRES_USER", passwordKey: "POSTGRES_PASSWORD", databaseKey: "POSTGRES_DB", dataPath: "/var/lib/postgresql/data", scheme: "postgres"},
		simpleDriver{name: "mysql", version: "8.4", image: "mysql", port: 3306, userKey: "MYSQL_USER", passwordKey: "MYSQL_PASSWORD", databaseKey: "MYSQL_DATABASE", rootPasswordKey: "MYSQL_ROOT_PASSWORD", dataPath: "/var/lib/mysql", scheme: "mysql"},
		simpleDriver{name: "mariadb", version: "11.8", image: "mariadb", port: 3306, userKey: "MARIADB_USER", passwordKey: "MARIADB_PASSWORD", databaseKey: "MARIADB_DATABASE", rootPasswordKey: "MARIADB_ROOT_PASSWORD", dataPath: "/var/lib/mysql", scheme: "mysql"},
		simpleDriver{name: "mongo", version: "8", image: "mongo", port: 27017, userKey: "MONGO_INITDB_ROOT_USERNAME", passwordKey: "MONGO_INITDB_ROOT_PASSWORD", databaseKey: "MONGO_INITDB_DATABASE", dataPath: "/data/db", scheme: "mongodb"},
		simpleDriver{name: "valkey", version: "8", image: "valkey/valkey", port: 6379, dataPath: "/data", scheme: "redis", commandPassword: true},
		simpleDriver{name: "redis", version: "8", image: "redis", port: 6379, dataPath: "/data", scheme: "redis", commandPassword: true},
		simpleDriver{name: "libsql", version: "latest", image: "ghcr.io/tursodatabase/libsql-server", port: 8080, passwordKey: "SQLD_AUTH_JWT_KEY", dataPath: "/var/lib/sqld", scheme: "http"},
		simpleDriver{name: "clickhouse", version: "25", image: "clickhouse/clickhouse-server", port: 8123, userKey: "CLICKHOUSE_USER", passwordKey: "CLICKHOUSE_PASSWORD", databaseKey: "CLICKHOUSE_DB", dataPath: "/var/lib/clickhouse", scheme: "http"},
		simpleDriver{name: "qdrant", version: "v1.15", image: "qdrant/qdrant", port: 6333, passwordKey: "QDRANT__SERVICE__API_KEY", dataPath: "/qdrant/storage", scheme: "http"},
		simpleDriver{name: "meilisearch", version: "v1.20", image: "getmeili/meilisearch", port: 7700, passwordKey: "MEILI_MASTER_KEY", dataPath: "/meili_data", scheme: "http"},
	} {
		r.drivers[d.Name()] = d
	}
	return r
}
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.drivers))
	for name := range r.drivers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
	if err := validateNativePlan(version, host, credentials, filename); err != nil {
		return BackupPlan{}, err
	}
	switch engine {
	case "postgres":
		return BackupPlan{Image: "postgres:" + version, Command: []string{"pg_dump", "--host", host, "--username", credentials["username"], "--dbname", credentials["database"], "--format=custom", "--file", "/backup/" + filename}, Environment: map[string]string{"PGPASSWORD": credentials["password"]}, Extension: "dump"}, nil
	case "mysql":
		return BackupPlan{Image: "mysql:" + version, Command: []string{"mysqldump", "--host", host, "--user", credentials["username"], "--single-transaction", "--routines", "--events", "--no-tablespaces", "--result-file=/backup/" + filename, credentials["database"]}, Environment: map[string]string{"MYSQL_PWD": credentials["password"]}, Extension: "sql"}, nil
	case "mariadb":
		return BackupPlan{Image: "mariadb:" + version, Command: []string{"mariadb-dump", "--host", host, "--user", credentials["username"], "--single-transaction", "--routines", "--events", "--result-file=/backup/" + filename, credentials["database"]}, Environment: map[string]string{"MYSQL_PWD": credentials["password"]}, Extension: "sql"}, nil
	case "mongo":
		configName := filename + ".config"
		return BackupPlan{Image: "mongo:" + version, Command: []string{"mongodump", "--config=/backup/" + configName, "--host", host, "--username", credentials["username"], "--authenticationDatabase", "admin", "--db", credentials["database"], "--archive=/backup/" + filename, "--gzip"}, Extension: "archive.gz", Files: map[string]string{configName: "password: " + mongoYAMLString(credentials["password"]) + "\n"}}, nil
	default:
		return BackupPlan{}, fmt.Errorf("verified backups are not implemented for database engine %q", engine)
	}
}

func (r *Registry) Restore(engine, version, host string, credentials map[string]string, filename string) (RestorePlan, error) {
	if driver, ok := r.drivers[engine].(*externalDriver); ok {
		return driver.Restore(version, host, credentials, filename)
	}
	if err := validateNativePlan(version, host, credentials, filename); err != nil {
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
	case "mongo":
		return "archive.gz", true
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
	default:
		return BackupPlan{}, fmt.Errorf("readiness probe is not implemented for database engine %q", engine)
	}
}

func validateNativePlan(version, host string, credentials map[string]string, filename string) error {
	if !safeVersion.MatchString(version) || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`).MatchString(host) || !regexp.MustCompile(`^[a-f0-9-]+\.(dump|sql|archive\.gz)$`).MatchString(filename) {
		return errors.New("invalid native backup parameters")
	}
	for _, key := range []string{"username", "password", "database"} {
		if credentials[key] == "" {
			return fmt.Errorf("database credential %q is missing", key)
		}
	}
	return nil
}

func mongoYAMLString(value string) string {
	data, _ := yaml.Marshal(value)
	return strings.TrimSpace(string(data))
}

type simpleDriver struct {
	name, version, image                                                 string
	port                                                                 int
	userKey, passwordKey, databaseKey, rootPasswordKey, dataPath, scheme string
	commandPassword                                                      bool
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
		service["command"] = []any{"valkey-server", "--appendonly", "yes", "--requirepass", "${DATABASE_PASSWORD}"}
		env["DATABASE_PASSWORD"] = password
	}
	doc := map[string]any{"services": map[string]any{req.Name: service}, "volumes": map[string]any{req.Name + "-data": map[string]any{}}, "networks": map[string]any{"default": map[string]any{"attachable": true}}}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return Result{}, err
	}
	auth := ""
	if user != "" {
		auth = user + ":" + password + "@"
	}
	url := fmt.Sprintf("%s://%s%s:%d/%s", d.scheme, auth, req.Name, d.port, databaseName)
	if d.scheme == "http" {
		url = fmt.Sprintf("http://%s:%d", req.Name, d.port)
	}
	return Result{ComposeYAML: string(out), Environment: env, Credentials: credentials, InternalURL: url, Version: req.Version}, nil
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
