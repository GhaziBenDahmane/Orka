package database

const libSQLUtilityImage = "python:3.13-alpine"

func libSQLEnvironment(host string, credentials map[string]string, filename string) map[string]string {
	return map[string]string{
		"DOCKYARD_LIBSQL_HOST":     host,
		"DOCKYARD_LIBSQL_PORT":     nativePort(credentials, 8080),
		"DOCKYARD_LIBSQL_USER":     credentials["username"],
		"DOCKYARD_LIBSQL_PASSWORD": credentials["password"],
		"DOCKYARD_LIBSQL_ARTIFACT": filename,
	}
}

func libSQLBackupPlan(host string, credentials map[string]string, filename string) BackupPlan {
	return BackupPlan{Image: libSQLUtilityImage, Command: []string{"python3", "-c", libSQLBackupScript}, Environment: libSQLEnvironment(host, credentials, filename), Extension: "sql"}
}

func libSQLRestorePlan(host string, credentials map[string]string, filename string) RestorePlan {
	return RestorePlan{Image: libSQLUtilityImage, Command: []string{"python3", "-c", libSQLRestoreScript}, Environment: libSQLEnvironment(host, credentials, filename), Extension: "sql"}
}

func libSQLReadinessPlan(host string, credentials map[string]string) BackupPlan {
	return BackupPlan{
		Image:   libSQLUtilityImage,
		Command: []string{"python3", "-c", libSQLReadinessScript},
		Environment: map[string]string{
			"DOCKYARD_LIBSQL_HOST":     host,
			"DOCKYARD_LIBSQL_PORT":     nativePort(credentials, 8080),
			"DOCKYARD_LIBSQL_USER":     credentials["username"],
			"DOCKYARD_LIBSQL_PASSWORD": credentials["password"],
		},
	}
}

const libSQLBackupScript = `
import base64
import os
import shutil
import urllib.request

base = "http://%s:%s" % (os.environ["DOCKYARD_LIBSQL_HOST"], os.environ["DOCKYARD_LIBSQL_PORT"])
credentials = (os.environ["DOCKYARD_LIBSQL_USER"] + ":" + os.environ["DOCKYARD_LIBSQL_PASSWORD"]).encode()
headers = {"authorization": "Basic " + base64.b64encode(credentials).decode()}
request = urllib.request.Request(base + "/dump?preserve_row_ids=true", headers=headers)
with urllib.request.urlopen(request, timeout=300) as response, open("/backup/" + os.environ["DOCKYARD_LIBSQL_ARTIFACT"], "wb") as output:
    shutil.copyfileobj(response, output, length=1024 * 1024)
`

const libSQLRestoreScript = `
import base64
import json
import os
import sqlite3
import urllib.error
import urllib.request

base = "http://%s:%s" % (os.environ["DOCKYARD_LIBSQL_HOST"], os.environ["DOCKYARD_LIBSQL_PORT"])
credentials = (os.environ["DOCKYARD_LIBSQL_USER"] + ":" + os.environ["DOCKYARD_LIBSQL_PASSWORD"]).encode()
headers = {"authorization": "Basic " + base64.b64encode(credentials).decode(), "content-type": "application/json"}
source = "/backup/" + os.environ["DOCKYARD_LIBSQL_ARTIFACT"]

def post(path, value):
    data = json.dumps(value, separators=(",", ":")).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers=headers, method="POST"), timeout=300) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError("libSQL request failed with HTTP %d: %s" % (error.code, error.read()[:512].decode(errors="replace")))

def pipeline(statements, baton=None, close=False):
    requests = [{"type": "execute", "stmt": {"sql": statement}} for statement in statements]
    if close:
        requests.append({"type": "close"})
    body = {"requests": requests}
    if baton is not None:
        body["baton"] = baton
    response = post("/v2/pipeline", body)
    for result in response.get("results", []):
        if result.get("type") != "ok":
            raise RuntimeError("libSQL statement failed: %s" % result.get("error"))
    return response.get("baton")

schema = post("/", {"statements": ["SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND type IN ('trigger','view','table') ORDER BY CASE type WHEN 'trigger' THEN 1 WHEN 'view' THEN 2 ELSE 3 END"]})
rows = schema[0]["results"]["rows"]
drop = []
for object_type, name in rows:
    if object_type not in ("trigger", "view", "table") or not isinstance(name, str):
        raise RuntimeError("invalid libSQL schema metadata")
    quoted = '"' + name.replace('"', '""') + '"'
    drop.append("DROP %s IF EXISTS %s" % (object_type.upper(), quoted))

baton = None
try:
    baton = pipeline(["PRAGMA foreign_keys=OFF", "BEGIN IMMEDIATE"])
    for offset in range(0, len(drop), 100):
        baton = pipeline(drop[offset:offset + 100], baton)
    batch = []
    batch_bytes = 0
    statement = ""
    with open(source, "r", encoding="utf-8") as dump:
        for line in dump:
            statement += line
            if not sqlite3.complete_statement(statement):
                continue
            sql = statement.strip()
            statement = ""
            normalized = sql.rstrip(";").strip().upper()
            if normalized not in ("BEGIN TRANSACTION", "COMMIT", "PRAGMA FOREIGN_KEYS=OFF"):
                batch.append(sql)
                batch_bytes += len(sql)
            if len(batch) >= 100 or batch_bytes >= 1024 * 1024:
                baton = pipeline(batch, baton)
                batch = []
                batch_bytes = 0
    if statement.strip():
        raise RuntimeError("incomplete SQL statement in libSQL backup")
    if batch:
        baton = pipeline(batch, baton)
    pipeline(["COMMIT", "PRAGMA foreign_keys=ON"], baton, True)
except Exception:
    if baton is not None:
        try:
            pipeline(["ROLLBACK"], baton, True)
        except Exception:
            pass
    raise
`

const libSQLReadinessScript = `
import base64
import json
import os
import urllib.request

base = "http://%s:%s" % (os.environ["DOCKYARD_LIBSQL_HOST"], os.environ["DOCKYARD_LIBSQL_PORT"])
credentials = (os.environ["DOCKYARD_LIBSQL_USER"] + ":" + os.environ["DOCKYARD_LIBSQL_PASSWORD"]).encode()
headers = {"authorization": "Basic " + base64.b64encode(credentials).decode(), "content-type": "application/json"}
body = json.dumps({"statements": ["SELECT 1"]}).encode()
with urllib.request.urlopen(urllib.request.Request(base + "/", data=body, headers=headers, method="POST"), timeout=10) as response:
    result = json.load(response)
    if result[0].get("error") is not None:
        raise RuntimeError("libSQL is not ready")
`
