package database

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
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
}
type RestorePlan = BackupPlan
type Registry struct{ drivers map[string]Driver }

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
	return driver.Render(request)
}

func (r *Registry) Backup(engine, version, host string, credentials map[string]string, filename string) (BackupPlan, error) {
	switch engine {
	case "postgres":
		return BackupPlan{Image: "postgres:" + version, Command: []string{"pg_dump", "--host", host, "--username", credentials["username"], "--dbname", credentials["database"], "--format=custom", "--file", "/backup/" + filename}, Environment: map[string]string{"PGPASSWORD": credentials["password"]}, Extension: "dump"}, nil
	default:
		return BackupPlan{}, fmt.Errorf("verified backups are not implemented for database engine %q", engine)
	}
}

func (r *Registry) Restore(engine, version, host string, credentials map[string]string, filename string) (RestorePlan, error) {
	switch engine {
	case "postgres":
		return RestorePlan{Image: "postgres:" + version, Command: []string{"pg_restore", "--clean", "--if-exists", "--no-owner", "--host", host, "--username", credentials["username"], "--dbname", credentials["database"], "/backup/" + filename}, Environment: map[string]string{"PGPASSWORD": credentials["password"]}, Extension: "dump"}, nil
	default:
		return RestorePlan{}, fmt.Errorf("verified restore is not implemented for database engine %q", engine)
	}
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
	user := "dockyard"
	database := "app"
	password := secret(32)
	env := map[string]string{}
	credentials := map[string]string{"username": user, "password": password, "database": database}
	if d.userKey != "" {
		env[d.userKey] = user
	}
	if d.passwordKey != "" {
		env[d.passwordKey] = password
	}
	if d.databaseKey != "" {
		env[d.databaseKey] = database
	}
	if d.rootPasswordKey != "" {
		env[d.rootPasswordKey] = secret(32)
	}
	service := map[string]any{"image": d.image + ":" + req.Version, "volumes": []any{req.Name + "-data:" + d.dataPath}, "networks": []any{"default"}, "deploy": map[string]any{"restart_policy": map[string]any{"condition": "on-failure"}}}
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
	url := fmt.Sprintf("%s://%s%s:%d/%s", d.scheme, auth, req.Name, d.port, database)
	if d.scheme == "http" {
		url = fmt.Sprintf("http://%s:%d", req.Name, d.port)
	}
	return Result{ComposeYAML: string(out), Environment: env, Credentials: credentials, InternalURL: url, Version: req.Version}, nil
}
func secret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")[:n]
}
