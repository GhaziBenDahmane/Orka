package database

func clickHouseEnvironment(host string, credentials map[string]string, filename string) map[string]string {
	return map[string]string{
		"CLICKHOUSE_PASSWORD":          credentials["password"],
		"DOCKYARD_CLICKHOUSE_HOST":     host,
		"DOCKYARD_CLICKHOUSE_PORT":     nativePort(credentials, 9000),
		"DOCKYARD_CLICKHOUSE_USER":     credentials["username"],
		"DOCKYARD_CLICKHOUSE_DATABASE": credentials["database"],
		"DOCKYARD_CLICKHOUSE_ARTIFACT": filename,
	}
}

func clickHouseBackupPlan(version, host string, credentials map[string]string, filename string) BackupPlan {
	return BackupPlan{Image: "clickhouse/clickhouse-server:" + version, Command: []string{"sh", "-eu", "-c", clickHouseBackupScript}, Environment: clickHouseEnvironment(host, credentials, filename), Extension: "tar.gz"}
}

func clickHouseRestorePlan(version, host string, credentials map[string]string, filename string) RestorePlan {
	return RestorePlan{Image: "clickhouse/clickhouse-server:" + version, Command: []string{"sh", "-eu", "-c", clickHouseRestoreScript}, Environment: clickHouseEnvironment(host, credentials, filename), Extension: "tar.gz"}
}

func clickHouseReadinessPlan(version, host string, credentials map[string]string) BackupPlan {
	return BackupPlan{
		Image:   "clickhouse/clickhouse-server:" + version,
		Command: []string{"clickhouse-client", "--host", host, "--port", nativePort(credentials, 9000), "--user", credentials["username"], "--database", credentials["database"], "--query", "SELECT 1"},
		Environment: map[string]string{
			"CLICKHOUSE_PASSWORD": credentials["password"],
		},
	}
}

const clickHouseBackupScript = `
work="/backup/.clickhouse-${DOCKYARD_CLICKHOUSE_ARTIFACT}"
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/schemas" "$work/data"
client() {
  clickhouse-client --host "$DOCKYARD_CLICKHOUSE_HOST" --port "$DOCKYARD_CLICKHOUSE_PORT" --user "$DOCKYARD_CLICKHOUSE_USER" --database "$DOCKYARD_CLICKHOUSE_DATABASE" "$@"
}
client --param_database "$DOCKYARD_CLICKHOUSE_DATABASE" --query "SELECT base64Encode(name),toUInt8(has_own_data OR (engine='MaterializedView' AND positionCaseInsensitive(create_table_query,' TO ')=0)) FROM system.tables WHERE database={database:String} AND NOT startsWith(name,'.inner_id.') ORDER BY multiIf(engine='MaterializedView',1,engine IN ('View','LiveView','WindowView','Dictionary'),2,0),name FORMAT TabSeparatedRaw" >"$work/tables.tsv"
: >"$work/manifest.tsv"
index=0
while IFS="$(printf '\t')" read -r encoded_name has_data; do
  test -n "$encoded_name" || continue
  table_name="$(printf '%s' "$encoded_name" | base64 -d)"
  printf '%s\t%s\t%s\n' "$index" "$encoded_name" "$has_data" >>"$work/manifest.tsv"
  client --param_database "$DOCKYARD_CLICKHOUSE_DATABASE" --param_table "$table_name" --show_table_uuid_in_table_create_query_if_not_nil=0 --query "SHOW CREATE TABLE {database:Identifier}.{table:Identifier}" --format TSVRaw >"$work/schemas/$index.sql"
  if test "$has_data" = "1"; then
    client --param_database "$DOCKYARD_CLICKHOUSE_DATABASE" --param_table "$table_name" --query "SELECT * FROM {database:Identifier}.{table:Identifier} FORMAT Native" >"$work/data/$index.native"
  fi
  index=$((index + 1))
done <"$work/tables.tsv"
tar -czf "/backup/$DOCKYARD_CLICKHOUSE_ARTIFACT" -C "$work" manifest.tsv schemas data
`

const clickHouseRestoreScript = `
work="/backup/.clickhouse-${DOCKYARD_CLICKHOUSE_ARTIFACT}"
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work"
tar -xzf "/backup/$DOCKYARD_CLICKHOUSE_ARTIFACT" -C "$work"
test -f "$work/manifest.tsv"
client() {
  clickhouse-client --host "$DOCKYARD_CLICKHOUSE_HOST" --port "$DOCKYARD_CLICKHOUSE_PORT" --user "$DOCKYARD_CLICKHOUSE_USER" --database "$DOCKYARD_CLICKHOUSE_DATABASE" "$@"
}
clickhouse-client --host "$DOCKYARD_CLICKHOUSE_HOST" --port "$DOCKYARD_CLICKHOUSE_PORT" --user "$DOCKYARD_CLICKHOUSE_USER" --database default --multiquery --param_database "$DOCKYARD_CLICKHOUSE_DATABASE" --query "DROP DATABASE IF EXISTS {database:Identifier}; CREATE DATABASE {database:Identifier}"
while IFS="$(printf '\t')" read -r index encoded_name has_data; do
  case "$index" in ''|*[!0-9]*) echo "invalid ClickHouse backup manifest" >&2; exit 1;; esac
  test -f "$work/schemas/$index.sql"
  table_name="$(printf '%s' "$encoded_name" | base64 -d)"
  client --multiquery <"$work/schemas/$index.sql"
  if test "$has_data" = "1"; then
    test -f "$work/data/$index.native"
    client --param_database "$DOCKYARD_CLICKHOUSE_DATABASE" --param_table "$table_name" --query "INSERT INTO {database:Identifier}.{table:Identifier} FORMAT Native" <"$work/data/$index.native"
  elif test "$has_data" != "0"; then
    echo "invalid ClickHouse backup manifest" >&2
    exit 1
  fi
done <"$work/manifest.tsv"
`
